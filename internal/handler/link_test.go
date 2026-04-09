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
	"github.com/hanej/passport/internal/idp"
)

// linkStubRenderer creates a Renderer with stubs needed for link tests.
func linkStubRenderer(t *testing.T) *Renderer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	funcMap := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"pages":    func(n int) []int { return nil },
	}
	pages := make(map[string]*template.Template)
	pages["dashboard.html"] = template.Must(template.New("dashboard.html").Funcs(funcMap).Parse(`{{define "base"}}dashboard{{end}}`))
	pages["error.html"] = template.Must(template.New("error.html").Funcs(funcMap).Parse(`{{define "base"}}error page{{end}}`))

	return &Renderer{pages: pages, logger: logger}
}

type linkTestEnv struct {
	db       *db.DB
	sm       *auth.SessionManager
	handler  *LinkHandler
	registry *idp.Registry
	auditLog *audit.Logger
}

func setupLinkTest(t *testing.T) *linkTestEnv {
	t.Helper()

	database := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := linkStubRenderer(t)
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

	h := NewLinkHandler(database, sm, registry, renderer, auditLog, logger)

	return &linkTestEnv{
		db:       database,
		sm:       sm,
		handler:  h,
		registry: registry,
		auditLog: auditLog,
	}
}

func (env *linkTestEnv) createSessionWithCookies(t *testing.T, userType, providerID, username string) []*http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := env.sm.CreateSession(rec, req, userType, providerID, username, false, false)
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}
	return rec.Result().Cookies()
}

func (env *linkTestEnv) serveWithSession(t *testing.T, handler http.HandlerFunc, method, path string, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
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

func TestLinkAccountSuccess(t *testing.T) {
	env := setupLinkTest(t)

	// Create the IDP record in the database (required for FK constraint on mappings).
	if err := env.db.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-ad",
		FriendlyName: "Corporate AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   `{}`,
	}); err != nil {
		t.Fatalf("creating IDP record: %v", err)
	}

	// Register a mock provider that accepts authentication.
	env.registry.Register("corp-ad", &mockProvider{
		id:           "corp-ad",
		providerType: idp.ProviderTypeAD,
	})

	cookies := env.createSessionWithCookies(t, "provider", "auth-idp", "jdoe")

	form := url.Values{}
	form.Set("idp_id", "corp-ad")
	form.Set("username", "cn=jdoe,ou=users,dc=example,dc=com")
	form.Set("password", "secret")

	rec := env.serveWithSession(t, env.handler.LinkAccount, http.MethodPost, "/dashboard/link-account", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d; body: %s", http.StatusFound, rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if loc != "/dashboard" {
		t.Errorf("expected redirect to /dashboard, got %s", loc)
	}

	// Verify the mapping was created.
	mapping, err := env.db.GetMapping(context.Background(), "auth-idp", "jdoe", "corp-ad")
	if err != nil {
		t.Fatalf("expected mapping to exist: %v", err)
	}
	if mapping.LinkType != "manual" {
		t.Errorf("expected link_type=manual, got %s", mapping.LinkType)
	}
	if mapping.TargetAccountDN != "cn=jdoe,ou=users,dc=example,dc=com" {
		t.Errorf("expected target_account_dn to be set, got %s", mapping.TargetAccountDN)
	}
}

func TestLinkAccountAuthFailure(t *testing.T) {
	env := setupLinkTest(t)

	// Register a mock provider that rejects authentication.
	env.registry.Register("corp-ad", &mockProvider{
		id:           "corp-ad",
		providerType: idp.ProviderTypeAD,
		authErr:      fmt.Errorf("invalid credentials"),
	})

	cookies := env.createSessionWithCookies(t, "provider", "auth-idp", "jdoe")

	form := url.Values{}
	form.Set("idp_id", "corp-ad")
	form.Set("username", "cn=jdoe,ou=users,dc=example,dc=com")
	form.Set("password", "wrong")

	rec := env.serveWithSession(t, env.handler.LinkAccount, http.MethodPost, "/dashboard/link-account", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "/dashboard" {
		t.Errorf("expected redirect to /dashboard, got %s", loc)
	}

	// Verify no mapping was created.
	_, err := env.db.GetMapping(context.Background(), "auth-idp", "jdoe", "corp-ad")
	if err == nil {
		t.Error("expected no mapping to exist after auth failure")
	}
}

func TestLinkAccountMissingFields(t *testing.T) {
	env := setupLinkTest(t)
	cookies := env.createSessionWithCookies(t, "provider", "auth-idp", "jdoe")

	form := url.Values{}
	form.Set("idp_id", "corp-ad")
	form.Set("username", "")
	form.Set("password", "secret")

	rec := env.serveWithSession(t, env.handler.LinkAccount, http.MethodPost, "/dashboard/link-account", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "/dashboard" {
		t.Errorf("expected redirect to /dashboard, got %s", loc)
	}
}

func TestLinkAccountProviderNotAvailable(t *testing.T) {
	env := setupLinkTest(t)
	cookies := env.createSessionWithCookies(t, "provider", "auth-idp", "jdoe")

	form := url.Values{}
	form.Set("idp_id", "nonexistent")
	form.Set("username", "jdoe")
	form.Set("password", "secret")

	rec := env.serveWithSession(t, env.handler.LinkAccount, http.MethodPost, "/dashboard/link-account", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, rec.Code)
	}
}

func TestLinkAccount_NoSession(t *testing.T) {
	// Call directly without session middleware → sess == nil → redirect to /login.
	env := setupLinkTest(t)
	req := httptest.NewRequest(http.MethodPost, "/dashboard/link-account", nil)
	rec := httptest.NewRecorder()
	env.handler.LinkAccount(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected /login, got %s", loc)
	}
}

func TestLinkAccount_LocalAdmin(t *testing.T) {
	// Local admin session → block with error redirect.
	env := setupLinkTest(t)
	cookies := env.createSessionWithCookies(t, "local", "", "admin")

	form := url.Values{}
	form.Set("idp_id", "corp-ad")
	form.Set("username", "jdoe")
	form.Set("password", "secret")

	rec := env.serveWithSession(t, env.handler.LinkAccount, http.MethodPost, "/dashboard/link-account", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected /dashboard, got %s", loc)
	}
}

func TestLinkAccount_DuplicateTargetBlocked(t *testing.T) {
	// If a mapping to the target IDP already exists (from any auth provider),
	// the manual link should be rejected to prevent duplicate rows.
	env := setupLinkTest(t)

	// Create IDP records for both the pre-existing mapping source and the target.
	for _, rec := range []*db.IdentityProviderRecord{
		{ID: "other-ad", FriendlyName: "Other AD", ProviderType: "ad", Enabled: true, ConfigJSON: `{}`},
		{ID: "freeipa", FriendlyName: "FreeIPA", ProviderType: "freeipa", Enabled: true, ConfigJSON: `{}`},
	} {
		if err := env.db.CreateIDP(context.Background(), rec); err != nil {
			t.Fatalf("creating IDP record %s: %v", rec.ID, err)
		}
	}

	env.registry.Register("freeipa", &mockProvider{
		id:           "freeipa",
		providerType: idp.ProviderTypeFreeIPA,
	})

	// Pre-create a mapping from a different auth provider to the same target.
	now := time.Now().UTC()
	if err := env.db.UpsertMapping(context.Background(), &db.UserIDPMapping{
		AuthProviderID:  "other-ad",
		AuthUsername:    "jdoe",
		TargetIDPID:     "freeipa",
		TargetAccountDN: "uid=jdoe,ou=users,dc=example,dc=com",
		LinkType:        "auto",
		LinkedAt:        now,
		VerifiedAt:      &now,
	}); err != nil {
		t.Fatalf("creating pre-existing mapping: %v", err)
	}

	// Log in via a different auth provider and attempt manual link.
	cookies := env.createSessionWithCookies(t, "provider", "auth-idp", "jdoe")

	form := url.Values{}
	form.Set("idp_id", "freeipa")
	form.Set("username", "uid=jdoe,ou=users,dc=example,dc=com")
	form.Set("password", "secret")

	rec := env.serveWithSession(t, env.handler.LinkAccount, http.MethodPost, "/dashboard/link-account", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected redirect to /dashboard, got %s", loc)
	}

	// Verify no second mapping was created.
	mappings, err := env.db.ListMappings(context.Background(), "", "jdoe")
	if err != nil {
		t.Fatalf("listing mappings: %v", err)
	}
	count := 0
	for _, m := range mappings {
		if m.TargetIDPID == "freeipa" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 mapping to freeipa, got %d", count)
	}
}

func TestLinkAccount_UserNotFoundError(t *testing.T) {
	// Auth error containing "user not found" → specific error message path.
	env := setupLinkTest(t)
	env.registry.Register("corp-ad", &mockProvider{
		id:      "corp-ad",
		authErr: fmt.Errorf("user not found in directory"),
	})

	cookies := env.createSessionWithCookies(t, "provider", "auth-idp", "jdoe")

	form := url.Values{}
	form.Set("idp_id", "corp-ad")
	form.Set("username", "jdoe")
	form.Set("password", "secret")

	rec := env.serveWithSession(t, env.handler.LinkAccount, http.MethodPost, "/dashboard/link-account", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
}

// mockLinkErrStore wraps *db.DB with injectable errors for link-related operations.
type mockLinkErrStore struct {
	*db.DB
	upsertMappingErr            error
	deleteCorrelationWarningErr error
}

func (m *mockLinkErrStore) UpsertMapping(ctx context.Context, mapping *db.UserIDPMapping) error {
	if m.upsertMappingErr != nil {
		return m.upsertMappingErr
	}
	return m.DB.UpsertMapping(ctx, mapping)
}

func (m *mockLinkErrStore) DeleteCorrelationWarning(ctx context.Context, authUsername, targetIDPID string) error {
	if m.deleteCorrelationWarningErr != nil {
		return m.deleteCorrelationWarningErr
	}
	return m.DB.DeleteCorrelationWarning(ctx, authUsername, targetIDPID)
}

func setupLinkTestWithStore(t *testing.T, store db.Store, database *db.DB) *linkTestEnv {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := linkStubRenderer(t)
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

	h := NewLinkHandler(store, sm, registry, renderer, auditLog, logger)
	return &linkTestEnv{
		db:       database,
		sm:       sm,
		handler:  h,
		registry: registry,
		auditLog: auditLog,
	}
}

// TestLinkAccount_UpsertMappingError covers the UpsertMapping error path (lines 147-164).
func TestLinkAccount_UpsertMappingError(t *testing.T) {
	database := setupTestDB(t)

	// Create IDP record in real DB so HasMappingToTarget and FK lookups work.
	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-ad",
		FriendlyName: "Corp AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   `{}`,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	mock := &mockLinkErrStore{DB: database, upsertMappingErr: fmt.Errorf("db write failed")}
	env := setupLinkTestWithStore(t, mock, database)

	env.registry.Register("corp-ad", &mockProvider{
		id:           "corp-ad",
		providerType: idp.ProviderTypeAD,
	})

	cookies := env.createSessionWithCookies(t, "provider", "auth-idp", "jdoe")

	form := url.Values{}
	form.Set("idp_id", "corp-ad")
	form.Set("username", "cn=jdoe,ou=users,dc=example,dc=com")
	form.Set("password", "secret")

	rec := env.serveWithSession(t, env.handler.LinkAccount, http.MethodPost, "/dashboard/link-account", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected /dashboard, got %s", loc)
	}
}

// TestLinkAccount_DeleteCorrelationWarningError covers the soft error at line 168.
// UpsertMapping succeeds but DeleteCorrelationWarning fails — still redirects to /dashboard.
func TestLinkAccount_DeleteCorrelationWarningError(t *testing.T) {
	database := setupTestDB(t)

	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-ad",
		FriendlyName: "Corp AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   `{}`,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	mock := &mockLinkErrStore{DB: database, deleteCorrelationWarningErr: fmt.Errorf("warning delete failed")}
	env := setupLinkTestWithStore(t, mock, database)

	env.registry.Register("corp-ad", &mockProvider{
		id:           "corp-ad",
		providerType: idp.ProviderTypeAD,
	})

	cookies := env.createSessionWithCookies(t, "provider", "auth-idp", "jdoe")

	form := url.Values{}
	form.Set("idp_id", "corp-ad")
	form.Set("username", "cn=jdoe,ou=users,dc=example,dc=com")
	form.Set("password", "secret")

	rec := env.serveWithSession(t, env.handler.LinkAccount, http.MethodPost, "/dashboard/link-account", cookies, form.Encode())

	// Soft error: redirect still happens.
	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected /dashboard, got %s", loc)
	}
}
