package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/idp"
	"github.com/hanej/passport/internal/job"
	"github.com/hanej/passport/internal/ratelimit"
)

// buildTestRouter creates a fully wired RouterConfig using the given test DB.
func buildTestRouter(t *testing.T, secureCookie bool, uploadsDir string, withLimiters bool) http.Handler {
	t.Helper()

	database := setupTestDB(t)
	logger := testLogger()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	cryptoSvc, err := crypto.NewService(key, 1)
	if err != nil {
		t.Fatalf("creating crypto: %v", err)
	}

	sm := auth.NewSessionManager(database, 30*time.Minute, secureCookie, logger)
	registry := idp.NewRegistry(logger)
	renderer := loginStubRenderer(t)

	tmpFile, err := os.CreateTemp(t.TempDir(), "audit-*.log")
	if err != nil {
		t.Fatalf("creating audit file: %v", err)
	}
	_ = tmpFile.Close()

	auditLog, err := audit.NewLogger(database, tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("creating audit logger: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })

	correlator := &mockCorrelator{}
	notifier := job.New(database, registry, cryptoSvc, auditLog, logger)

	// Doc content: pass nil (empty) to avoid needing specific embedded files.
	var docContent []byte

	csrfKey := make([]byte, 32)

	var loginLimiter *ratelimit.Limiter
	var linkLimiter *ratelimit.Limiter
	if withLimiters {
		loginLimiter = ratelimit.NewLimiter(10, 10, logger)
		linkLimiter = ratelimit.NewLimiter(10, 10, logger)
	}

	uploadsPath := uploadsDir
	if uploadsPath == "" {
		uploadsPath = t.TempDir()
	}

	cfg := RouterConfig{
		Health:              NewHealthHandler(database, logger),
		Login:               NewLoginHandler(database, sm, registry, correlator, cryptoSvc, renderer, auditLog, logger),
		ForgotPassword:      NewForgotPasswordHandler(database, registry, sm, renderer, auditLog, logger),
		Dashboard:           NewDashboardHandler(database, sm, registry, correlator, renderer, auditLog, logger),
		Link:                NewLinkHandler(database, sm, registry, renderer, auditLog, logger),
		Bootstrap:           NewBootstrapHandler(database, sm, renderer, auditLog, logger),
		AdminIDP:            NewAdminIDPHandler(database, cryptoSvc, registry, renderer, auditLog, logger, uploadsPath),
		AdminSMTP:           NewAdminSMTPHandler(database, cryptoSvc, renderer, auditLog, logger),
		AdminGroups:         NewAdminGroupsHandler(database, registry, renderer, auditLog, logger),
		AdminMappings:       NewAdminMappingsHandler(database, registry, renderer, auditLog, logger),
		AdminAudit:          NewAdminAuditHandler(database, renderer, logger),
		AdminMFA:            NewAdminMFAHandler(database, cryptoSvc, renderer, auditLog, logger),
		AdminEmailTemplates: NewAdminEmailTemplatesHandler(database, renderer, sm, auditLog, logger),
		AdminExpiration:     NewAdminExpirationHandler(database, notifier, renderer, auditLog, logger),
		AdminBranding:       NewAdminBrandingHandler(database, renderer, auditLog, logger, uploadsPath),
		AdminMigrate:        NewAdminMigrateHandler(database, cryptoSvc, renderer, auditLog, logger),
		AdminDocs:           NewAdminDocsHandler(renderer, logger, docContent),
		MFA:                 NewMFAHandler(database, sm, cryptoSvc, registry, renderer, auditLog, logger),
		Sessions:            sm,
		CSRFKey:             csrfKey,
		SecureCookie:        secureCookie,
		LoginLimiter:        loginLimiter,
		LinkLimiter:         linkLimiter,
		UploadsDir:          uploadsPath,
		Logger:              logger,
	}

	return NewRouter(cfg)
}

func TestRequestLogger(t *testing.T) {
	logger := testLogger()
	mw := requestLogger(logger)

	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusTeapot)
	})

	wrapped := mw(inner)
	req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if !reached {
		t.Error("inner handler was not called")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("expected 418, got %d", rec.Code)
	}
}

func TestNewRouter_Healthz(t *testing.T) {
	router := buildTestRouter(t, false, "", false)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 from /healthz, got %d", rec.Code)
	}
}

func TestNewRouter_RootRedirect(t *testing.T) {
	router := buildTestRouter(t, false, "", false)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 redirect from /, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected redirect to /login, got %s", loc)
	}
}

func TestNewRouter_WithLimiterBranch(t *testing.T) {
	// Exercises cfg.LoginLimiter != nil and cfg.LinkLimiter != nil branches.
	router := buildTestRouter(t, false, "", true)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestNewRouter_SecureCookieBranch(t *testing.T) {
	// Exercises the !cfg.SecureCookie branch (plaintext HTTP middleware).
	router := buildTestRouter(t, false, "", false)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestNewRouter_StaticFiles(t *testing.T) {
	// Exercises the static file serving route.
	router := buildTestRouter(t, false, "", false)

	// Request a known static asset (bootstrap CSS is embedded).
	req := httptest.NewRequest(http.MethodGet, "/static/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Either OK or directory listing is fine; just shouldn't 404 hard.
	if rec.Code == http.StatusInternalServerError {
		t.Errorf("unexpected 500 for /static/")
	}
}

func TestNewRouter_WithUploadsDir(t *testing.T) {
	uploadsDir := t.TempDir()
	// Create a test file in uploads dir.
	if err := os.WriteFile(uploadsDir+"/test.txt", []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	router := buildTestRouter(t, false, uploadsDir, false)

	req := httptest.NewRequest(http.MethodGet, "/uploads/test.txt", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for uploaded file, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "hello") {
		t.Errorf("expected file content, got: %s", rec.Body.String())
	}
}
