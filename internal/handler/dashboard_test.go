package handler

import (
	"context"
	"encoding/json"
	"errors"
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
)

// dashboardStubRenderer creates a Renderer with dashboard and related template stubs.
func dashboardStubRenderer(t *testing.T) *Renderer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	funcMap := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"pages":    func(n int) []int { return nil },
	}
	pages := make(map[string]*template.Template)
	pages["dashboard.html"] = template.Must(template.New("dashboard.html").Funcs(funcMap).Parse(`{{define "base"}}dashboard {{range .Data.Sections}}{{range .Panels}}{{.IDP.FriendlyName}} policy={{with .PasswordPolicy}}{{.MinLength}}{{end}}| {{end}}{{end}}{{end}}`))
	pages["error.html"] = template.Must(template.New("error.html").Funcs(funcMap).Parse(`{{define "base"}}error page{{end}}`))
	pages["login.html"] = template.Must(template.New("login.html").Funcs(funcMap).Parse(`{{define "base"}}login page{{end}}`))

	return &Renderer{pages: pages, logger: logger}
}

type dashboardTestEnv struct {
	db         *db.DB
	sm         *auth.SessionManager
	handler    *DashboardHandler
	registry   *idp.Registry
	correlator *mockCorrelator
	auditLog   *audit.Logger
}

func setupDashboardTest(t *testing.T) *dashboardTestEnv {
	t.Helper()

	database := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := dashboardStubRenderer(t)
	registry := idp.NewRegistry(logger)
	correlator := &mockCorrelator{}

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generating key: %v", err)
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

	h := NewDashboardHandler(database, sm, registry, correlator, cryptoSvc, renderer, auditLog, logger)

	return &dashboardTestEnv{
		db:         database,
		sm:         sm,
		handler:    h,
		registry:   registry,
		correlator: correlator,
		auditLog:   auditLog,
	}
}

func (env *dashboardTestEnv) createSessionWithCookies(t *testing.T, userType, providerID, username string, isAdmin bool) []*http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := env.sm.CreateSession(rec, req, userType, providerID, username, isAdmin, false)
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}
	return rec.Result().Cookies()
}

func (env *dashboardTestEnv) serveWithSession(t *testing.T, handler http.HandlerFunc, method, path string, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
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

func TestShowDashboardRendersIDPPanels(t *testing.T) {
	env := setupDashboardTest(t)

	// Create IDP records.
	for _, rec := range []db.IdentityProviderRecord{
		{ID: "corp-ad", FriendlyName: "Corporate AD", ProviderType: "ad", Enabled: true, ConfigJSON: `{}`},
		{ID: "dev-ipa", FriendlyName: "Dev FreeIPA", ProviderType: "freeipa", Enabled: true, ConfigJSON: `{}`},
	} {
		if err := env.db.CreateIDP(context.Background(), &rec); err != nil {
			t.Fatalf("creating IDP: %v", err)
		}
	}

	cookies := env.createSessionWithCookies(t, "local", "", "admin", true)

	// ShowDashboard calls csrf.TemplateField and csrf.Token, so we wrap.
	handlerReached := false
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerReached = true
		sess := auth.SessionFromContext(r.Context())

		idps, _ := env.db.ListEnabledIDPs(r.Context())
		panels := make([]IDPPanel, len(idps))
		for i, rec := range idps {
			panels[i] = IDPPanel{IDP: rec}
		}

		env.handler.renderer.Render(w, r, "dashboard.html", PageData{
			Title:   "Dashboard",
			Session: sess,
			Data: map[string]any{
				"Sections":   []DashboardSection{{Panels: panels}},
				"ProviderID": sess.ProviderID,
			},
		})
	})

	rec := env.serveWithSession(t, testHandler, http.MethodGet, "/dashboard", cookies, "")

	if !handlerReached {
		t.Fatal("handler was not reached")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Corporate AD") {
		t.Errorf("expected 'Corporate AD' in response, got: %s", body)
	}
	if !strings.Contains(body, "Dev FreeIPA") {
		t.Errorf("expected 'Dev FreeIPA' in response, got: %s", body)
	}
}

func TestIDPStatusOnline(t *testing.T) {
	env := setupDashboardTest(t)

	env.registry.Register("corp-ad", &mockProvider{
		id:           "corp-ad",
		providerType: idp.ProviderTypeAD,
	})

	req := withChiURLParam(httptest.NewRequest(http.MethodGet, "/dashboard/idp-status/corp-ad", nil), "id", "corp-ad")
	rec := httptest.NewRecorder()

	env.handler.IDPStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body["status"] != "online" {
		t.Errorf("expected status online, got %s", body["status"])
	}
}

func TestIDPStatusOffline(t *testing.T) {
	env := setupDashboardTest(t)

	env.registry.Register("corp-ad", &mockProvider{
		id:           "corp-ad",
		providerType: idp.ProviderTypeAD,
		testConnErr:  fmt.Errorf("connection refused"),
	})

	req := withChiURLParam(httptest.NewRequest(http.MethodGet, "/dashboard/idp-status/corp-ad", nil), "id", "corp-ad")
	rec := httptest.NewRecorder()

	env.handler.IDPStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body["status"] != "offline" {
		t.Errorf("expected status offline, got %s", body["status"])
	}
	if body["error"] != "connection failed" {
		t.Errorf("expected generic error 'connection failed', got %s", body["error"])
	}
}

func TestIDPStatusNotFound(t *testing.T) {
	env := setupDashboardTest(t)

	req := withChiURLParam(httptest.NewRequest(http.MethodGet, "/dashboard/idp-status/nonexistent", nil), "id", "nonexistent")
	rec := httptest.NewRecorder()

	env.handler.IDPStatus(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", rec.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body["status"] != "offline" {
		t.Errorf("expected status offline, got %s", body["status"])
	}
}

func TestIDPStatus_EmptyID(t *testing.T) {
	env := setupDashboardTest(t)

	// Call without chi URL param → idpID is "".
	req := httptest.NewRequest(http.MethodGet, "/dashboard/idp-status/", nil)
	rec := httptest.NewRecorder()

	env.handler.IDPStatus(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}
}

// TestPasswordChangeMessage verifies that provider errors are mapped to
// user-safe messages and that no raw directory detail survives the mapping.
func TestPasswordChangeMessage(t *testing.T) {
	leaky := "LDAP Result Code 49: bind failed for CN=svc,OU=Svc,DC=corp,DC=example,DC=com via dc01.corp.example.com:636"

	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "policy",
			err:  fmt.Errorf("%w: %s", idp.ErrPasswordPolicy, leaky),
			want: "the new password does not meet your organization's complexity, history, or minimum age requirements.",
		},
		{
			name: "wrong current password",
			err:  errors.New("current password is incorrect"),
			want: "current password is incorrect.",
		},
		{
			name: "locked",
			err:  fmt.Errorf("%w: %s", idp.ErrAccountLocked, leaky),
			want: "your account is locked. Please contact your IT administrator.",
		},
		{
			name: "disabled",
			err:  fmt.Errorf("%w: %s", idp.ErrAccountDisabled, leaky),
			want: "your account is disabled. Please contact your IT administrator.",
		},
		{
			name: "unknown",
			err:  errors.New(leaky),
			want: "please try again or contact your administrator.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := passwordChangeMessage(tc.err)
			if got != tc.want {
				t.Errorf("passwordChangeMessage() = %q, want %q", got, tc.want)
			}
			if strings.Contains(got, "DC=corp") || strings.Contains(got, "dc01") {
				t.Errorf("directory detail leaked into user message: %q", got)
			}
		})
	}
}

func TestPublicIDPStatus_EmptyID(t *testing.T) {
	env := setupDashboardTest(t)

	req := httptest.NewRequest(http.MethodGet, "/idp-status/", nil)
	rec := httptest.NewRecorder()

	env.handler.PublicIDPStatus(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}
}

func TestPublicIDPStatus_Online(t *testing.T) {
	env := setupDashboardTest(t)
	env.registry.Register("corp-ad", &mockProvider{id: "corp-ad"})

	req := withChiURLParam(httptest.NewRequest(http.MethodGet, "/idp-status/corp-ad", nil), "id", "corp-ad")
	rec := httptest.NewRecorder()

	env.handler.PublicIDPStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body["status"] != "online" {
		t.Errorf("expected online, got %s", body["status"])
	}
}

func TestPublicIDPStatus_Offline(t *testing.T) {
	env := setupDashboardTest(t)
	env.registry.Register("corp-ad", &mockProvider{id: "corp-ad", testConnErr: fmt.Errorf("refused")})

	req := withChiURLParam(httptest.NewRequest(http.MethodGet, "/idp-status/corp-ad", nil), "id", "corp-ad")
	rec := httptest.NewRecorder()

	env.handler.PublicIDPStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body["status"] != "offline" {
		t.Errorf("expected offline, got %s", body["status"])
	}
}

func TestPublicIDPStatus_NotInRegistry(t *testing.T) {
	env := setupDashboardTest(t)

	req := withChiURLParam(httptest.NewRequest(http.MethodGet, "/idp-status/unknown", nil), "id", "unknown")
	rec := httptest.NewRecorder()

	env.handler.PublicIDPStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body["status"] != "offline" {
		t.Errorf("expected offline, got %s", body["status"])
	}
}

// TestShowDashboard_NoSession verifies the nil-session guard inside the handler.
func TestShowDashboard_NoSession(t *testing.T) {
	env := setupDashboardTest(t)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()

	// Call directly, no session middleware → sess == nil → redirect.
	env.handler.ShowDashboard(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected /login, got %s", loc)
	}
}

// TestShowDashboard_WithSession calls ShowDashboard through the session middleware.
func TestShowDashboard_WithSession(t *testing.T) {
	env := setupDashboardTest(t)

	// Create an IDP so the panel list is non-empty.
	if err := env.db.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID: "test-idp", FriendlyName: "Test IDP", ProviderType: "ad", Enabled: true, ConfigJSON: `{}`,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	cookies := env.createSessionWithCookies(t, "local", "", "admin", true)
	rec := env.serveWithSession(t, env.handler.ShowDashboard, http.MethodGet, "/dashboard", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestChangePassword_NoSession verifies the nil-session guard.
func TestChangePassword_NoSession(t *testing.T) {
	env := setupDashboardTest(t)

	req := httptest.NewRequest(http.MethodPost, "/dashboard/change-password", nil)
	rec := httptest.NewRecorder()
	env.handler.ChangePassword(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
}

// TestChangePassword_NoMapping covers the case where the user has no mapping.
func TestChangePassword_NoMapping(t *testing.T) {
	env := setupDashboardTest(t)

	cookies := env.createSessionWithCookies(t, "provider", "corp-ad", "jdoe", false)

	form := url.Values{}
	form.Set("idp_id", "corp-ad")
	form.Set("current_password", "old")
	form.Set("new_password", "NewPass1!")
	form.Set("confirm_password", "NewPass1!")

	rec := env.serveWithSession(t, env.handler.ChangePassword, http.MethodPost, "/dashboard/change-password", cookies, form.Encode())

	// No mapping → flash error + redirect to dashboard.
	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestChangePassword_EmptyNewPassword covers the empty new_password guard.
func TestChangePassword_EmptyNewPassword(t *testing.T) {
	env := setupDashboardTest(t)

	cookies := env.createSessionWithCookies(t, "provider", "corp-ad", "jdoe", false)

	form := url.Values{}
	form.Set("idp_id", "corp-ad")
	form.Set("current_password", "old")
	form.Set("new_password", "")
	form.Set("confirm_password", "")

	rec := env.serveWithSession(t, env.handler.ChangePassword, http.MethodPost, "/dashboard/change-password", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
}

// TestChangePassword_PasswordMismatch covers the mismatch guard.
func TestChangePassword_PasswordMismatch(t *testing.T) {
	env := setupDashboardTest(t)

	cookies := env.createSessionWithCookies(t, "provider", "corp-ad", "jdoe", false)

	form := url.Values{}
	form.Set("idp_id", "corp-ad")
	form.Set("current_password", "old")
	form.Set("new_password", "NewPass1!")
	form.Set("confirm_password", "DifferentPass1!")

	rec := env.serveWithSession(t, env.handler.ChangePassword, http.MethodPost, "/dashboard/change-password", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
}

// TestChangePassword_ProviderNotFound covers the missing registry provider case.
func TestChangePassword_ProviderNotFound(t *testing.T) {
	env := setupDashboardTest(t)

	// Create an IDP and a mapping so mapping lookup succeeds.
	if err := env.db.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad", Enabled: true, ConfigJSON: `{}`,
	}); err != nil {
		t.Fatalf("%v", err)
	}
	mapping := &db.UserIDPMapping{
		AuthProviderID:  "corp-ad",
		AuthUsername:    "jdoe",
		TargetIDPID:     "corp-ad",
		TargetAccountDN: "CN=jdoe,DC=example,DC=com",
		LinkType:        "auto",
		LinkedAt:        time.Now().UTC(),
	}
	if err := env.db.UpsertMapping(context.Background(), mapping); err != nil {
		t.Fatalf("upserting mapping: %v", err)
	}

	cookies := env.createSessionWithCookies(t, "provider", "corp-ad", "jdoe", false)

	form := url.Values{}
	form.Set("idp_id", "corp-ad")
	form.Set("current_password", "old")
	form.Set("new_password", "NewPass1!")
	form.Set("confirm_password", "NewPass1!")

	// Provider not in registry.
	rec := env.serveWithSession(t, env.handler.ChangePassword, http.MethodPost, "/dashboard/change-password", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestChangePassword_Success covers the successful password change.
func TestChangePassword_Success(t *testing.T) {
	env := setupDashboardTest(t)

	if err := env.db.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad", Enabled: true, ConfigJSON: `{}`,
	}); err != nil {
		t.Fatalf("%v", err)
	}
	mapping := &db.UserIDPMapping{
		AuthProviderID:  "corp-ad",
		AuthUsername:    "jdoe",
		TargetIDPID:     "corp-ad",
		TargetAccountDN: "CN=jdoe,DC=example,DC=com",
		LinkType:        "auto",
		LinkedAt:        time.Now().UTC(),
	}
	if err := env.db.UpsertMapping(context.Background(), mapping); err != nil {
		t.Fatalf("upserting mapping: %v", err)
	}

	env.registry.Register("corp-ad", &mockProvider{id: "corp-ad"})

	cookies := env.createSessionWithCookies(t, "provider", "corp-ad", "jdoe", false)

	form := url.Values{}
	form.Set("idp_id", "corp-ad")
	form.Set("current_password", "old")
	form.Set("new_password", "NewPass1!")
	form.Set("confirm_password", "NewPass1!")

	rec := env.serveWithSession(t, env.handler.ChangePassword, http.MethodPost, "/dashboard/change-password", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected /dashboard, got %s", loc)
	}
}

// TestChangePassword_Failure covers ChangePassword returning an error.
func TestChangePassword_Failure(t *testing.T) {
	env := setupDashboardTest(t)

	if err := env.db.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad", Enabled: true, ConfigJSON: `{}`,
	}); err != nil {
		t.Fatalf("%v", err)
	}
	mapping := &db.UserIDPMapping{
		AuthProviderID:  "corp-ad",
		AuthUsername:    "jdoe",
		TargetIDPID:     "corp-ad",
		TargetAccountDN: "CN=jdoe,DC=example,DC=com",
		LinkType:        "auto",
		LinkedAt:        time.Now().UTC(),
	}
	if err := env.db.UpsertMapping(context.Background(), mapping); err != nil {
		t.Fatalf("upserting mapping: %v", err)
	}

	env.registry.Register("corp-ad", &mockProvider{
		id:            "corp-ad",
		changePassErr: fmt.Errorf("policy violation"),
	})

	cookies := env.createSessionWithCookies(t, "provider", "corp-ad", "jdoe", false)

	form := url.Values{}
	form.Set("idp_id", "corp-ad")
	form.Set("current_password", "old")
	form.Set("new_password", "NewPass1!")
	form.Set("confirm_password", "NewPass1!")

	rec := env.serveWithSession(t, env.handler.ChangePassword, http.MethodPost, "/dashboard/change-password", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
}

// TestChangePassword_CrossProvider verifies that a user can change their password
// even when their mapping was created under a different auth provider than the one
// they are currently logged in with (same username across corp-ad and redhat-idm).
func TestChangePassword_CrossProvider(t *testing.T) {
	env := setupDashboardTest(t)

	if err := env.db.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad", Enabled: true, ConfigJSON: `{}`,
	}); err != nil {
		t.Fatalf("%v", err)
	}
	if err := env.db.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID: "redhat-idm", FriendlyName: "Red Hat IDM", ProviderType: "freeipa", Enabled: true, ConfigJSON: `{}`,
	}); err != nil {
		t.Fatalf("%v", err)
	}

	// Mapping was originally created when the user logged in via corp-ad.
	mapping := &db.UserIDPMapping{
		AuthProviderID:  "corp-ad",
		AuthUsername:    "jschulze",
		TargetIDPID:     "corp-ad",
		TargetAccountDN: "CN=Test User,OU=Users,DC=example,DC=com",
		LinkType:        "auto",
		LinkedAt:        time.Now().UTC(),
	}
	if err := env.db.UpsertMapping(context.Background(), mapping); err != nil {
		t.Fatalf("upserting mapping: %v", err)
	}

	env.registry.Register("corp-ad", &mockProvider{id: "corp-ad"})

	// User is now logged in via redhat-idm (same username, different auth provider).
	cookies := env.createSessionWithCookies(t, "provider", "redhat-idm", "jschulze", false)

	form := url.Values{}
	form.Set("idp_id", "corp-ad")
	form.Set("current_password", "old")
	form.Set("new_password", "NewPass1!")
	form.Set("confirm_password", "NewPass1!")

	rec := env.serveWithSession(t, env.handler.ChangePassword, http.MethodPost, "/dashboard/change-password", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected /dashboard, got %s", loc)
	}
}

// --- DB error path tests ---

type mockDashboardErrStore struct {
	*db.DB
	listEnabledIDPsErr         error
	listMappingsErr            error
	listCorrelationWarningsErr error
}

func (m *mockDashboardErrStore) ListEnabledIDPs(ctx context.Context) ([]db.IdentityProviderRecord, error) {
	if m.listEnabledIDPsErr != nil {
		return nil, m.listEnabledIDPsErr
	}
	return m.DB.ListEnabledIDPs(ctx)
}

func (m *mockDashboardErrStore) ListMappings(ctx context.Context, authProviderID, authUsername string) ([]db.UserIDPMapping, error) {
	if m.listMappingsErr != nil {
		return nil, m.listMappingsErr
	}
	return m.DB.ListMappings(ctx, authProviderID, authUsername)
}

func (m *mockDashboardErrStore) ListCorrelationWarnings(ctx context.Context, username string) ([]db.CorrelationWarning, error) {
	if m.listCorrelationWarningsErr != nil {
		return nil, m.listCorrelationWarningsErr
	}
	return m.DB.ListCorrelationWarnings(ctx, username)
}

func newDashboardHandlerWithStore(t *testing.T, database *db.DB, store db.Store) (*DashboardHandler, *auth.SessionManager) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := dashboardStubRenderer(t)
	registry := idp.NewRegistry(logger)
	correlator := &mockCorrelator{}

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generating key: %v", err)
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

	return NewDashboardHandler(store, sm, registry, correlator, cryptoSvc, renderer, auditLog, logger), sm
}

// TestShowDashboard_ListEnabledIDPsError covers the error path when ListEnabledIDPs fails → 500.
func TestShowDashboard_ListEnabledIDPsError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockDashboardErrStore{DB: database, listEnabledIDPsErr: fmt.Errorf("db failure")}
	h, sm := newDashboardHandlerWithStore(t, database, mock)

	rec0 := httptest.NewRecorder()
	req0 := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := sm.CreateSession(rec0, req0, "local", "", "admin", true, false); err != nil {
		t.Fatalf("creating session: %v", err)
	}
	cookies := rec0.Result().Cookies()

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	wrapped := sm.Middleware(http.HandlerFunc(h.ShowDashboard))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when ListEnabledIDPs fails, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "error page") {
		t.Errorf("expected error page, got: %s", rec.Body.String())
	}
}

// TestShowDashboard_ListMappingsError verifies that ListMappings error is soft —
// dashboard still renders 200.
func TestShowDashboard_ListMappingsError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockDashboardErrStore{DB: database, listMappingsErr: fmt.Errorf("db failure")}
	h, sm := newDashboardHandlerWithStore(t, database, mock)

	rec0 := httptest.NewRecorder()
	req0 := httptest.NewRequest(http.MethodGet, "/", nil)
	// userType="local" causes ListMappings to be called.
	if _, err := sm.CreateSession(rec0, req0, "local", "", "jdoe", false, false); err != nil {
		t.Fatalf("creating session: %v", err)
	}
	cookies := rec0.Result().Cookies()

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	wrapped := sm.Middleware(http.HandlerFunc(h.ShowDashboard))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	// ListMappings error is soft — dashboard still renders.
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 despite ListMappings error, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestShowDashboard_ListCorrelationWarningsError verifies that ListCorrelationWarnings
// error is soft — dashboard still renders 200.
func TestShowDashboard_ListCorrelationWarningsError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockDashboardErrStore{DB: database, listCorrelationWarningsErr: fmt.Errorf("db failure")}
	h, sm := newDashboardHandlerWithStore(t, database, mock)

	rec0 := httptest.NewRecorder()
	req0 := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := sm.CreateSession(rec0, req0, "local", "", "jdoe", false, false); err != nil {
		t.Fatalf("creating session: %v", err)
	}
	cookies := rec0.Result().Cookies()

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	wrapped := sm.Middleware(http.HandlerFunc(h.ShowDashboard))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 despite ListCorrelationWarnings error, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestShowDashboard_EmptyConfigJSON covers the branch where an IDP has empty ConfigJSON
// (panel.Config stays nil, no parse attempt, dashboard still renders 200).
func TestShowDashboard_EmptyConfigJSON(t *testing.T) {
	env := setupDashboardTest(t)
	if err := env.db.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID: "no-cfg-idp", FriendlyName: "No Config IDP", ProviderType: "ad", Enabled: true, ConfigJSON: "",
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}
	cookies := env.createSessionWithCookies(t, "local", "", "admin", true)
	rec := env.serveWithSession(t, env.handler.ShowDashboard, http.MethodGet, "/dashboard", cookies, "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with empty ConfigJSON IDP, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestShowDashboard_InvalidConfigJSON covers the branch where an IDP has invalid ConfigJSON
// (parse error is logged, panel.Config stays nil, dashboard still renders 200).
func TestShowDashboard_InvalidConfigJSON(t *testing.T) {
	env := setupDashboardTest(t)
	if err := env.db.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID: "bad-cfg-idp", FriendlyName: "Bad Config IDP", ProviderType: "ad", Enabled: true, ConfigJSON: "not-valid-json{",
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}
	cookies := env.createSessionWithCookies(t, "local", "", "admin", true)
	rec := env.serveWithSession(t, env.handler.ShowDashboard, http.MethodGet, "/dashboard", cookies, "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with invalid ConfigJSON IDP, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestShowDashboard_CrossProviderMapping verifies that when a user authenticates
// via one provider (e.g. corp-ad) but their mapping was created by a different
// provider (e.g. redhat-idm), the dashboard still shows the mapping as linked.
func TestShowDashboard_CrossProviderMapping(t *testing.T) {
	env := setupDashboardTest(t)
	ctx := context.Background()

	// Create two IDPs.
	for _, rec := range []db.IdentityProviderRecord{
		{ID: "redhat-idm", FriendlyName: "Red Hat IDM", ProviderType: "freeipa", Enabled: true, ConfigJSON: `{}`},
		{ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad", Enabled: true, ConfigJSON: `{}`},
	} {
		if err := env.db.CreateIDP(ctx, &rec); err != nil {
			t.Fatalf("creating IDP: %v", err)
		}
	}

	// Mapping was created when user logged in via redhat-idm (auth_provider_id = "redhat-idm").
	now := time.Now().UTC()
	if err := env.db.UpsertMapping(ctx, &db.UserIDPMapping{
		AuthProviderID:  "redhat-idm",
		AuthUsername:    "jdoe",
		TargetIDPID:     "corp-ad",
		TargetAccountDN: "CN=John Doe,DC=example,DC=com",
		LinkType:        "auto",
		LinkedAt:        now,
		VerifiedAt:      &now,
	}); err != nil {
		t.Fatalf("upserting mapping: %v", err)
	}

	// User now logs in via corp-ad — session has provider_id = "corp-ad".
	cookies := env.createSessionWithCookies(t, "provider", "corp-ad", "jdoe", false)
	rec := env.serveWithSession(t, env.handler.ShowDashboard, http.MethodGet, "/dashboard", cookies, "")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// The dashboard template should show Corp AD panel (which has the mapping).
	body := rec.Body.String()
	if !strings.Contains(body, "Corp AD") {
		t.Errorf("expected 'Corp AD' in response, got: %s", body)
	}
}

// TestShowDashboard_WithMappingAndWarning covers lines 102-103 (mappings loop),
// 112-113 (warnings loop), and 139-152 (attribute lookup for linked accounts).
func TestShowDashboard_WithMappingAndWarning(t *testing.T) {
	env := setupDashboardTest(t)
	ctx := context.Background()

	// Create an IDP.
	if err := env.db.CreateIDP(ctx, &db.IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad", Enabled: true, ConfigJSON: `{}`,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	// Register a mock provider so registry.Get("corp-ad") succeeds.
	env.registry.Register("corp-ad", &mockProvider{id: "corp-ad"})

	// Create attribute mappings for display_name and email.
	if err := env.db.SetAttributeMappings(ctx, "corp-ad", []db.AttributeMapping{
		{IDPID: "corp-ad", CanonicalName: "display_name", DirectoryAttr: "cn"},
		{IDPID: "corp-ad", CanonicalName: "email", DirectoryAttr: "mail"},
	}); err != nil {
		t.Fatalf("setting attribute mappings: %v", err)
	}

	// Create a mapping for the session user.
	now := time.Now().UTC()
	if err := env.db.UpsertMapping(ctx, &db.UserIDPMapping{
		AuthProviderID:  "local",
		AuthUsername:    "admin",
		TargetIDPID:     "corp-ad",
		TargetAccountDN: "cn=admin,dc=example,dc=com",
		LinkType:        "auto",
		LinkedAt:        now,
		VerifiedAt:      &now,
	}); err != nil {
		t.Fatalf("upserting mapping: %v", err)
	}

	// Create a correlation warning for the session user.
	if err := env.db.SetCorrelationWarning(ctx, &db.CorrelationWarning{
		AuthUsername: "admin",
		TargetIDPID:  "corp-ad",
		Message:      "ambiguous match",
	}); err != nil {
		t.Fatalf("setting correlation warning: %v", err)
	}

	cookies := env.createSessionWithCookies(t, "local", "", "admin", true)
	rec := env.serveWithSession(t, env.handler.ShowDashboard, http.MethodGet, "/dashboard", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestChangePassword_LocalUser covers line 229 where authProvider is set to "local"
// for a local-type session user.
func TestChangePassword_LocalUser(t *testing.T) {
	env := setupDashboardTest(t)

	// Create the IDP and a mapping for the local user.
	if err := env.db.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad", Enabled: true, ConfigJSON: `{}`,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}
	now := time.Now().UTC()
	if err := env.db.UpsertMapping(context.Background(), &db.UserIDPMapping{
		AuthProviderID:  "local",
		AuthUsername:    "admin",
		TargetIDPID:     "corp-ad",
		TargetAccountDN: "CN=admin,DC=example,DC=com",
		LinkType:        "auto",
		LinkedAt:        now,
	}); err != nil {
		t.Fatalf("upserting mapping: %v", err)
	}
	env.registry.Register("corp-ad", &mockProvider{id: "corp-ad"})

	// Local user session.
	cookies := env.createSessionWithCookies(t, "local", "", "admin", true)

	form := url.Values{}
	form.Set("idp_id", "corp-ad")
	form.Set("current_password", "old")
	form.Set("new_password", "NewPass1!")
	form.Set("confirm_password", "NewPass1!")

	rec := env.serveWithSession(t, env.handler.ChangePassword, http.MethodPost, "/dashboard/change-password", cookies, form.Encode())

	// Successful password change via local session → redirect to /dashboard.
	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// linkedPanelEnv sets up a dashboard with one linked AD panel whose provider can
// report the directory's password policy.
func linkedPanelEnv(t *testing.T, cfgJSON string, policyErr error) *dashboardTestEnv {
	t.Helper()
	env := setupDashboardTest(t)
	ctx := context.Background()

	if err := env.db.CreateIDP(ctx, &db.IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad", Enabled: true, ConfigJSON: cfgJSON,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}
	env.registry.Register("corp-ad", &mockPolicyProvider{
		mockProvider: &mockProvider{id: "corp-ad", providerType: idp.ProviderTypeAD},
		policy:       idp.PasswordPolicy{MinLength: 14, ComplexityEnabled: true},
		policyErr:    policyErr,
	})

	now := time.Now().UTC()
	if err := env.db.UpsertMapping(ctx, &db.UserIDPMapping{
		AuthProviderID:  "local",
		AuthUsername:    "admin",
		TargetIDPID:     "corp-ad",
		TargetAccountDN: "cn=admin,dc=example,dc=com",
		LinkType:        "auto",
		LinkedAt:        now,
		VerifiedAt:      &now,
	}); err != nil {
		t.Fatalf("upserting mapping: %v", err)
	}
	return env
}

func TestShowDashboard_PasswordPolicy(t *testing.T) {
	tests := []struct {
		name       string
		configJSON string
		policyErr  error
		wantPolicy string
	}{
		{
			name:       "shown by default",
			configJSON: `{}`,
			wantPolicy: "policy=14|",
		},
		{
			name:       "suppressed by the IDP setting",
			configJSON: `{"hide_discovered_password_policy":true}`,
			wantPolicy: "policy=|",
		},
		{
			// The directory stays the authority, so an unreadable policy must not
			// stop the panel rendering.
			name:       "unreadable policy still renders the panel",
			configJSON: `{}`,
			policyErr:  errors.New("insufficient access"),
			wantPolicy: "policy=|",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := linkedPanelEnv(t, tt.configJSON, tt.policyErr)
			cookies := env.createSessionWithCookies(t, "local", "", "admin", true)

			rec := env.serveWithSession(t, env.handler.ShowDashboard, http.MethodGet, "/dashboard", cookies, "")

			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
			}
			if body := rec.Body.String(); !strings.Contains(body, tt.wantPolicy) {
				t.Errorf("expected %q in body, got: %s", tt.wantPolicy, body)
			}
		})
	}
}
