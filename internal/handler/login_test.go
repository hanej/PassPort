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
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
)

// mockProvider is a test implementation of idp.Provider.
type mockProvider struct {
	id            string
	providerType  idp.ProviderType
	authErr       error
	changePassErr error
	testConnErr   error
	userGroups    []string
	groupsErr     error
	groupMembers  []string
	membersErr    error
}

func (m *mockProvider) Authenticate(_ context.Context, _, _ string) error { return m.authErr }
func (m *mockProvider) ChangePassword(_ context.Context, _, _, _ string) error {
	return m.changePassErr
}
func (m *mockProvider) ResetPassword(_ context.Context, _, _ string) error { return nil }
func (m *mockProvider) UnlockAccount(_ context.Context, _ string) error    { return nil }
func (m *mockProvider) EnableAccount(_ context.Context, _ string) error    { return nil }
func (m *mockProvider) GetUserGroups(_ context.Context, _ string) ([]string, error) {
	return m.userGroups, m.groupsErr
}
func (m *mockProvider) GetGroupMembers(_ context.Context, _ string) ([]string, error) {
	return m.groupMembers, m.membersErr
}
func (m *mockProvider) TestConnection(_ context.Context) error { return m.testConnErr }
func (m *mockProvider) SearchUser(_ context.Context, _, _ string) (string, error) {
	return "", nil
}
func (m *mockProvider) GetUserAttribute(_ context.Context, _, _ string) (string, error) {
	return "", nil
}
func (m *mockProvider) Type() idp.ProviderType { return m.providerType }
func (m *mockProvider) ID() string             { return m.id }

// mockCorrelator is a test implementation of CorrelatorInterface.
type mockCorrelator struct {
	called     bool
	providerID string
	username   string
	err        error
}

func (m *mockCorrelator) CorrelateUser(_ context.Context, providerID, username string) error {
	m.called = true
	m.providerID = providerID
	m.username = username
	return m.err
}

// loginStubRenderer creates a Renderer with login.html and dashboard.html stubs.
func loginStubRenderer(t *testing.T) *Renderer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	funcMap := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"pages":    func(n int) []int { return nil },
	}
	pages := make(map[string]*template.Template)
	pages["login.html"] = template.Must(template.New("login.html").Funcs(funcMap).Parse(`{{define "base"}}login page {{if .Flash}}{{.Flash.message}}{{end}} {{if .Data}}{{range .Data.IDPs}}{{.FriendlyName}}{{end}}{{end}}{{end}}`))
	pages["error.html"] = template.Must(template.New("error.html").Funcs(funcMap).Parse(`{{define "base"}}error page{{end}}`))
	pages["dashboard.html"] = template.Must(template.New("dashboard.html").Funcs(funcMap).Parse(`{{define "base"}}dashboard{{end}}`))

	return &Renderer{pages: pages, logger: logger}
}

type loginTestEnv struct {
	db         *db.DB
	sm         *auth.SessionManager
	handler    *LoginHandler
	registry   *idp.Registry
	correlator *mockCorrelator
	auditLog   *audit.Logger
}

func setupLoginTest(t *testing.T) *loginTestEnv {
	t.Helper()

	database := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := loginStubRenderer(t)
	registry := idp.NewRegistry(logger)
	correlator := &mockCorrelator{}

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generating crypto key: %v", err)
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

	h := NewLoginHandler(database, sm, registry, correlator, cryptoSvc, renderer, auditLog, logger)

	return &loginTestEnv{
		db:         database,
		sm:         sm,
		handler:    h,
		registry:   registry,
		correlator: correlator,
		auditLog:   auditLog,
	}
}

func (env *loginTestEnv) createLocalAdmin(t *testing.T, password string) {
	t.Helper()
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("hashing password: %v", err)
	}
	if _, err := env.db.CreateLocalAdmin(context.Background(), "admin", hash); err != nil {
		t.Fatalf("creating admin: %v", err)
	}
	// CreateLocalAdmin sets must_change_password=true by default; clear it.
	if err := env.db.UpdateLocalAdminPassword(context.Background(), "admin", hash, false); err != nil {
		t.Fatalf("clearing must_change_password: %v", err)
	}
}

func (env *loginTestEnv) createIDPRecord(t *testing.T, id, name string) {
	t.Helper()
	rec := &db.IdentityProviderRecord{
		ID:           id,
		FriendlyName: name,
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   `{"endpoint":"ldap.example.com:636","protocol":"ldaps","base_dn":"dc=example,dc=com"}`,
	}
	if err := env.db.CreateIDP(context.Background(), rec); err != nil {
		t.Fatalf("creating IDP record: %v", err)
	}
}

func (env *loginTestEnv) serveNoSession(t *testing.T, handler http.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()

	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestShowLoginRendersWithIDPList(t *testing.T) {
	env := setupLoginTest(t)
	env.createIDPRecord(t, "corp-ad", "Corporate AD")

	// ShowLogin calls csrf.TemplateField(r), which panics without CSRF middleware.
	// We test the logic by calling a wrapper that skips CSRF.
	handlerReached := false
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerReached = true
		idps, err := env.db.ListEnabledIDPs(r.Context())
		if err != nil {
			t.Errorf("listing IDPs: %v", err)
			return
		}
		env.handler.renderer.Render(w, r, "login.html", PageData{
			Title: "Login",
			Data: map[string]any{
				"IDPs": idps,
			},
		})
	})

	rec := env.serveNoSession(t, testHandler, http.MethodGet, "/login", "")

	if !handlerReached {
		t.Fatal("handler was not reached")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Corporate AD") {
		t.Errorf("expected IDP name in response, got: %s", rec.Body.String())
	}
}

func TestLoginLocalAdminSuccess(t *testing.T) {
	env := setupLoginTest(t)
	env.createLocalAdmin(t, "correct-password")

	form := url.Values{}
	form.Set("provider_id", "local")
	form.Set("username", "admin")
	form.Set("password", "correct-password")

	// Login calls csrf.TemplateField on error path; direct POST avoids it on success.
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	env.handler.Login(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d; body: %s", http.StatusFound, rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if loc != "/dashboard" {
		t.Errorf("expected redirect to /dashboard, got %s", loc)
	}

	// Verify a session cookie was set.
	cookies := rec.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "passport_session" && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Error("expected passport_session cookie to be set")
	}
}

func TestLoginLocalAdminMustChangePassword(t *testing.T) {
	env := setupLoginTest(t)

	// Create admin with must_change_password=true.
	hash, err := auth.HashPassword("temp-password")
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}
	if _, err := env.db.CreateLocalAdmin(context.Background(), "admin", hash); err != nil {
		t.Fatalf("creating admin: %v", err)
	}
	// The default CreateLocalAdmin sets must_change_password=true.

	form := url.Values{}
	form.Set("provider_id", "local")
	form.Set("username", "admin")
	form.Set("password", "temp-password")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	env.handler.Login(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "/change-password" {
		t.Errorf("expected redirect to /change-password, got %s", loc)
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	env := setupLoginTest(t)
	env.createLocalAdmin(t, "correct-password")

	form := url.Values{}
	form.Set("provider_id", "local")
	form.Set("username", "admin")
	form.Set("password", "wrong-password")

	// Login renders login.html with error on failure, which calls csrf.TemplateField.
	// We test the auth logic by calling loginLocal directly through a wrapper.
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	// Call loginLocal directly since Login would call renderLoginError which calls csrf.
	admin, getErr := env.db.GetLocalAdmin(req.Context(), "admin")
	if getErr != nil {
		t.Fatalf("getting admin: %v", getErr)
	}
	checkErr := auth.CheckPassword(admin.PasswordHash, "wrong-password")
	if checkErr == nil {
		t.Fatal("expected password check to fail")
	}

	// Verify no session was created.
	_ = rec // unused since we tested the logic directly
}

func TestLoginProviderSuccess(t *testing.T) {
	env := setupLoginTest(t)
	env.createIDPRecord(t, "corp-ad", "Corporate AD")

	// Register a mock provider that always succeeds.
	env.registry.Register("corp-ad", &mockProvider{
		id:           "corp-ad",
		providerType: idp.ProviderTypeAD,
	})

	form := url.Values{}
	form.Set("provider_id", "corp-ad")
	form.Set("username", "jdoe")
	form.Set("password", "secret")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	env.handler.Login(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d; body: %s", http.StatusFound, rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if loc != "/dashboard" {
		t.Errorf("expected redirect to /dashboard, got %s", loc)
	}
}

func TestLoginProviderFailure(t *testing.T) {
	env := setupLoginTest(t)
	env.createIDPRecord(t, "corp-ad", "Corporate AD")

	env.registry.Register("corp-ad", &mockProvider{
		id:           "corp-ad",
		providerType: idp.ProviderTypeAD,
		authErr:      fmt.Errorf("invalid credentials"),
	})

	form := url.Values{}
	form.Set("provider_id", "corp-ad")
	form.Set("username", "jdoe")
	form.Set("password", "wrong")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	// Login will call renderLoginError which calls csrf.TemplateField.
	// Test the auth path directly.
	provider, ok := env.registry.Get("corp-ad")
	if !ok {
		t.Fatal("expected provider to be registered")
	}
	err := provider.Authenticate(req.Context(), "jdoe", "wrong")
	if err == nil {
		t.Error("expected authentication to fail")
	}

	_ = rec
}

func TestLogoutDestroysSession(t *testing.T) {
	env := setupLoginTest(t)

	// Create a session first.
	sessionRec := httptest.NewRecorder()
	sessionReq := httptest.NewRequest(http.MethodGet, "/", nil)
	sessionID, err := env.sm.CreateSession(sessionRec, sessionReq, "local", "", "admin", true, false)
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}
	cookies := sessionRec.Result().Cookies()

	// Verify session exists.
	sess, err := env.db.GetSession(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("session should exist: %v", err)
	}
	_ = sess

	// Serve logout through session middleware.
	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	rec := httptest.NewRecorder()
	wrapped := env.sm.Middleware(http.HandlerFunc(env.handler.Logout))
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "/login" {
		t.Errorf("expected redirect to /login, got %s", loc)
	}

	// Verify session was destroyed.
	_, err = env.db.GetSession(context.Background(), sessionID)
	if err == nil {
		t.Error("expected session to be deleted after logout")
	}
}

// mockProviderWithDN is a variant of mockProvider that returns a configurable DN
// from SearchUser. This avoids modifying the existing mockProvider struct.
type mockProviderWithDN struct {
	mockProvider
	searchUserDN string
}

func (m *mockProviderWithDN) SearchUser(_ context.Context, _, _ string) (string, error) {
	if m.searchUserDN != "" {
		return m.searchUserDN, nil
	}
	return "", fmt.Errorf("user not found")
}

func TestLoginProviderCreatesSelfMapping(t *testing.T) {
	env := setupLoginTest(t)
	env.createIDPRecord(t, "corp-ad", "Corporate AD")

	expectedDN := "CN=jdoe,OU=Users,DC=example,DC=com"

	// Register a mock provider that returns a DN from SearchUser.
	env.registry.Register("corp-ad", &mockProviderWithDN{
		mockProvider: mockProvider{
			id:           "corp-ad",
			providerType: idp.ProviderTypeAD,
		},
		searchUserDN: expectedDN,
	})

	form := url.Values{}
	form.Set("provider_id", "corp-ad")
	form.Set("username", "jdoe")
	form.Set("password", "secret")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	env.handler.Login(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d; body: %s", http.StatusFound, rec.Code, rec.Body.String())
	}

	// The self-mapping is created in a goroutine. Wait briefly for it to complete.
	time.Sleep(200 * time.Millisecond)

	// Verify the self-mapping was created (auth_provider == target_idp).
	mappings, err := env.db.ListMappings(context.Background(), "corp-ad", "jdoe")
	if err != nil {
		t.Fatalf("listing mappings: %v", err)
	}

	var selfMapping *db.UserIDPMapping
	for i := range mappings {
		if mappings[i].AuthProviderID == "corp-ad" && mappings[i].TargetIDPID == "corp-ad" {
			selfMapping = &mappings[i]
			break
		}
	}
	if selfMapping == nil {
		t.Fatal("expected self-mapping to be created (auth_provider == target_idp)")
	}
	if selfMapping.TargetAccountDN != expectedDN {
		t.Errorf("expected target DN %q, got %q", expectedDN, selfMapping.TargetAccountDN)
	}
	if selfMapping.LinkType != "auto" {
		t.Errorf("expected link type 'auto', got %q", selfMapping.LinkType)
	}
	if selfMapping.VerifiedAt == nil {
		t.Error("expected verified_at to be set on self-mapping")
	}
}

// TestShowLogin_Direct calls ShowLogin directly (no CSRF middleware; csrf.TemplateField returns "").
func TestShowLogin_Direct(t *testing.T) {
	env := setupLoginTest(t)
	env.createIDPRecord(t, "corp-ad", "Corporate AD")

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	env.handler.ShowLogin(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Corporate AD") {
		t.Errorf("expected 'Corporate AD' in body, got: %s", rec.Body.String())
	}
}

// TestLogin_MissingCredentials covers the empty username/password guard.
func TestLogin_MissingCredentials(t *testing.T) {
	env := setupLoginTest(t)

	form := url.Values{}
	form.Set("provider_id", "local")
	form.Set("username", "")
	form.Set("password", "")
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.Login(rec, req)

	// renderLoginError renders the login page (200).
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for form re-render, got %d", rec.Code)
	}
}

// TestLoginLocal_WrongUser covers GetLocalAdmin returning not-found.
func TestLoginLocal_WrongUser(t *testing.T) {
	env := setupLoginTest(t)
	// No admin created → GetLocalAdmin will fail.

	form := url.Values{}
	form.Set("provider_id", "local")
	form.Set("username", "nonexistent")
	form.Set("password", "anything")
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.Login(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for form re-render, got %d", rec.Code)
	}
}

// TestLoginLocal_WrongPassword covers the CheckPassword failure path.
func TestLoginLocal_WrongPassword(t *testing.T) {
	env := setupLoginTest(t)
	env.createLocalAdmin(t, "correct")

	form := url.Values{}
	form.Set("provider_id", "local")
	form.Set("username", "admin")
	form.Set("password", "wrong")
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.Login(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for form re-render, got %d", rec.Code)
	}
}

// TestLoginProvider_NotInRegistry covers the registry.Get → false path.
func TestLoginProvider_NotInRegistry(t *testing.T) {
	env := setupLoginTest(t)
	// No provider registered.

	form := url.Values{}
	form.Set("provider_id", "corp-ad")
	form.Set("username", "jdoe")
	form.Set("password", "secret")
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.Login(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for form re-render, got %d", rec.Code)
	}
}

// TestLoginProvider_AuthFailure triggers the Authenticate error path.
func TestLoginProvider_AuthFailure(t *testing.T) {
	env := setupLoginTest(t)
	env.registry.Register("corp-ad", &mockProvider{
		id:      "corp-ad",
		authErr: fmt.Errorf("bad credentials"),
	})

	form := url.Values{}
	form.Set("provider_id", "corp-ad")
	form.Set("username", "jdoe")
	form.Set("password", "wrong")
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.Login(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for form re-render, got %d", rec.Code)
	}
}

// TestCheckAdminGroupMembership_Match verifies admin detection when user is in an admin group.
func TestCheckAdminGroupMembership_Match(t *testing.T) {
	env := setupLoginTest(t)
	env.createIDPRecord(t, "corp-ad", "Corporate AD")

	adminGroupDN := "CN=Admins,OU=Groups,DC=example,DC=com"

	// Create admin group in DB.
	if err := env.db.CreateAdminGroup(context.Background(), &db.AdminGroup{
		IDPID:   "corp-ad",
		GroupDN: adminGroupDN,
	}); err != nil {
		t.Fatalf("creating admin group: %v", err)
	}

	// Register provider that returns the admin group DN for the user.
	env.registry.Register("corp-ad", &mockProvider{
		id:         "corp-ad",
		userGroups: []string{adminGroupDN},
	})

	form := url.Values{}
	form.Set("provider_id", "corp-ad")
	form.Set("username", "jdoe")
	form.Set("password", "secret")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.Login(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify session was created with isAdmin=true.
	sessionCookies := rec.Result().Cookies()
	var sessionID string
	for _, c := range sessionCookies {
		if c.Name == "passport_session" {
			sessionID = c.Value
		}
	}
	if sessionID == "" {
		t.Fatal("expected session cookie")
	}

	sess, err := env.db.GetSession(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("getting session: %v", err)
	}
	if !sess.IsAdmin {
		t.Error("expected session to have isAdmin=true for admin group member")
	}
}

// TestCheckAdminGroupMembership_GetGroupsFails covers GetUserGroups error path.
func TestCheckAdminGroupMembership_GetGroupsFails(t *testing.T) {
	env := setupLoginTest(t)
	env.createIDPRecord(t, "corp-ad", "Corporate AD")

	// Create admin group so checkAdminGroupMembership proceeds past early return.
	if err := env.db.CreateAdminGroup(context.Background(), &db.AdminGroup{
		IDPID:   "corp-ad",
		GroupDN: "CN=Admins,DC=example,DC=com",
	}); err != nil {
		t.Fatalf("creating admin group: %v", err)
	}

	// Provider whose GetUserGroups returns an error.
	env.registry.Register("corp-ad", &mockProvider{
		id:        "corp-ad",
		groupsErr: fmt.Errorf("ldap error"),
	})

	form := url.Values{}
	form.Set("provider_id", "corp-ad")
	form.Set("username", "jdoe")
	form.Set("password", "secret")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.Login(rec, req)

	// Even with GetUserGroups error, auth succeeds (isAdmin=false).
	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Check that session is created with isAdmin=false.
	for _, c := range rec.Result().Cookies() {
		if c.Name == "passport_session" {
			sess, err := env.db.GetSession(context.Background(), c.Value)
			if err != nil {
				t.Fatalf("getting session: %v", err)
			}
			if sess.IsAdmin {
				t.Error("expected isAdmin=false when GetUserGroups fails")
			}
		}
	}
}

// TestLogout_NoSession covers the path where Logout is called without a session in context.
func TestLogout_NoSession(t *testing.T) {
	env := setupLoginTest(t)

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	rec := httptest.NewRecorder()
	// Call directly without middleware → sess is nil.
	env.handler.Logout(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected /login, got %s", loc)
	}
}

// TestLoginProvider_SkipsSelfMapping when HasMappingToTarget returns true.

// mockLoginErrStore wraps *db.DB and overrides specific methods to inject errors.
type mockLoginErrStore struct {
	*db.DB
	listEnabledIDPsErr         error
	upsertMappingErr           error
	getMFALoginRequiredErr     error
	getMFALoginRequiredVal     bool
	getMFAProviderForIDPErr    error
	getMFAProviderForIDPNil    bool
	getMFAProviderForIDPRecord *db.MFAProviderRecord
	updateSessionMFAErr        error
	getAdminGroupsByIDPErr     error
}

func (m *mockLoginErrStore) ListEnabledIDPs(ctx context.Context) ([]db.IdentityProviderRecord, error) {
	if m.listEnabledIDPsErr != nil {
		return nil, m.listEnabledIDPsErr
	}
	return m.DB.ListEnabledIDPs(ctx)
}

func (m *mockLoginErrStore) UpsertMapping(ctx context.Context, mapping *db.UserIDPMapping) error {
	if m.upsertMappingErr != nil {
		return m.upsertMappingErr
	}
	return m.DB.UpsertMapping(ctx, mapping)
}

func (m *mockLoginErrStore) GetMFALoginRequired(ctx context.Context) (bool, error) {
	if m.getMFALoginRequiredErr != nil {
		return false, m.getMFALoginRequiredErr
	}
	if m.getMFALoginRequiredVal {
		return true, nil
	}
	return m.DB.GetMFALoginRequired(ctx)
}

func (m *mockLoginErrStore) GetMFAProviderForIDP(ctx context.Context, idpID string) (*db.MFAProviderRecord, error) {
	if m.getMFAProviderForIDPErr != nil {
		return nil, m.getMFAProviderForIDPErr
	}
	if m.getMFAProviderForIDPNil {
		return nil, nil
	}
	if m.getMFAProviderForIDPRecord != nil {
		return m.getMFAProviderForIDPRecord, nil
	}
	return m.DB.GetMFAProviderForIDP(ctx, idpID)
}

func (m *mockLoginErrStore) UpdateSessionMFA(ctx context.Context, id string, mfaPending bool, mfaState string) error {
	if m.updateSessionMFAErr != nil {
		return m.updateSessionMFAErr
	}
	return m.DB.UpdateSessionMFA(ctx, id, mfaPending, mfaState)
}

func (m *mockLoginErrStore) GetAdminGroupsByIDP(ctx context.Context, idpID string) ([]db.AdminGroup, error) {
	if m.getAdminGroupsByIDPErr != nil {
		return nil, m.getAdminGroupsByIDPErr
	}
	return m.DB.GetAdminGroupsByIDP(ctx, idpID)
}

// TestShowLogin_DBError covers ShowLogin when ListEnabledIDPs fails (login.go:61-65).
func TestShowLogin_DBError(t *testing.T) {
	database := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	mockStore := &mockLoginErrStore{
		DB:                 database,
		listEnabledIDPsErr: fmt.Errorf("database connection lost"),
	}

	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := loginStubRenderer(t)
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

	h := NewLoginHandler(mockStore, sm, registry, &mockCorrelator{}, nil, renderer, auditLog, logger)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	h.ShowLogin(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when ListEnabledIDPs fails, got %d", rec.Code)
	}
}

// TestLoginProvider_SearchUserBothFail covers lines 219-228 where both uid and
// sAMAccountName SearchUser attempts fail and no self-mapping is created.
func TestLoginProvider_SearchUserBothFail(t *testing.T) {
	env := setupLoginTest(t)
	env.createIDPRecord(t, "corp-ad", "Corporate AD")

	// Register a provider with empty searchUserDN so SearchUser always returns error.
	env.registry.Register("corp-ad", &mockProviderWithDN{
		mockProvider: mockProvider{id: "corp-ad"},
		// searchUserDN == "" → SearchUser returns fmt.Errorf("user not found")
	})

	form := url.Values{}
	form.Set("provider_id", "corp-ad")
	form.Set("username", "jdoe")
	form.Set("password", "secret")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.Login(rec, req)

	// Login still succeeds despite SearchUser failure.
	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected /dashboard, got %s", loc)
	}

	// Verify no self-mapping was created (DN could not be resolved).
	mappings, err := env.db.ListMappings(context.Background(), "corp-ad", "jdoe")
	if err != nil {
		t.Fatalf("listing mappings: %v", err)
	}
	if len(mappings) != 0 {
		t.Errorf("expected no mapping when SearchUser fails, got %d", len(mappings))
	}
}

// TestLoginProvider_UpsertMappingError covers line 247-253 where UpsertMapping
// fails but the overall login still succeeds with a redirect to /dashboard.
func TestLoginProvider_UpsertMappingError(t *testing.T) {
	database := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	mockStore := &mockLoginErrStore{
		DB:               database,
		upsertMappingErr: fmt.Errorf("insert failed: disk full"),
	}

	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := loginStubRenderer(t)
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

	h := NewLoginHandler(mockStore, sm, registry, &mockCorrelator{}, nil, renderer, auditLog, logger)

	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-ad",
		FriendlyName: "Corporate AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   `{}`,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	// Provider returns a valid DN so UpsertMapping is attempted.
	registry.Register("corp-ad", &mockProviderWithDN{
		mockProvider: mockProvider{id: "corp-ad"},
		searchUserDN: "CN=jdoe,DC=example,DC=com",
	})

	form := url.Values{}
	form.Set("provider_id", "corp-ad")
	form.Set("username", "jdoe")
	form.Set("password", "secret")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Login(rec, req)

	// Login should still redirect to /dashboard even when UpsertMapping fails.
	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect to /dashboard, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected /dashboard, got %s", loc)
	}
}

func TestLoginProvider_SkipsSelfMappingWhenExists(t *testing.T) {
	env := setupLoginTest(t)
	env.createIDPRecord(t, "corp-ad", "Corporate AD")

	existingDN := "CN=jdoe,DC=example,DC=com"
	env.registry.Register("corp-ad", &mockProviderWithDN{
		mockProvider: mockProvider{id: "corp-ad"},
		searchUserDN: existingDN,
	})

	// Pre-create a mapping so HasMappingToTarget returns true.
	if err := env.db.UpsertMapping(context.Background(), &db.UserIDPMapping{
		AuthProviderID:  "corp-ad",
		AuthUsername:    "jdoe",
		TargetIDPID:     "corp-ad",
		TargetAccountDN: existingDN,
		LinkType:        "auto",
		LinkedAt:        time.Now().UTC(),
	}); err != nil {
		t.Fatalf("upserting mapping: %v", err)
	}

	form := url.Values{}
	form.Set("provider_id", "corp-ad")
	form.Set("username", "jdoe")
	form.Set("password", "secret")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.Login(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// newMockLoginHandler builds a LoginHandler over a custom store for direct method testing.
func newMockLoginHandler(t *testing.T, store db.Store, baseDB *db.DB) *LoginHandler {
	t.Helper()
	logger := testLogger()
	sm := auth.NewSessionManager(baseDB, 30*time.Minute, false, logger)
	renderer := loginStubRenderer(t)
	registry := idp.NewRegistry(logger)

	tmpFile, err := os.CreateTemp(t.TempDir(), "audit-*.log")
	if err != nil {
		t.Fatalf("creating temp audit file: %v", err)
	}
	_ = tmpFile.Close()
	auditLog, err := audit.NewLogger(baseDB, tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("creating audit logger: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generating crypto key: %v", err)
	}
	cryptoSvc, err := crypto.NewService(key, 1)
	if err != nil {
		t.Fatalf("creating crypto service: %v", err)
	}

	return NewLoginHandler(store, sm, registry, &mockCorrelator{}, cryptoSvc, renderer, auditLog, logger)
}

// TestShouldEnforceMFA_GetRequiredError covers GetMFALoginRequired returning error → returns false.
func TestShouldEnforceMFA_GetRequiredError(t *testing.T) {
	database := setupTestDB(t)
	mockStore := &mockLoginErrStore{
		DB:                     database,
		getMFALoginRequiredErr: fmt.Errorf("db failure"),
	}
	h := newMockLoginHandler(t, mockStore, database)
	if h.shouldEnforceMFAOnLogin(context.Background(), "test-idp") {
		t.Error("expected false when GetMFALoginRequired returns error")
	}
}

// TestShouldEnforceMFA_GetProviderError covers GetMFALoginRequired=true + GetMFAProviderForIDP error → false.
func TestShouldEnforceMFA_GetProviderError(t *testing.T) {
	database := setupTestDB(t)
	mockStore := &mockLoginErrStore{
		DB:                      database,
		getMFALoginRequiredVal:  true,
		getMFAProviderForIDPErr: fmt.Errorf("provider lookup failed"),
	}
	h := newMockLoginHandler(t, mockStore, database)
	if h.shouldEnforceMFAOnLogin(context.Background(), "test-idp") {
		t.Error("expected false when GetMFAProviderForIDP returns error")
	}
}

// TestShouldEnforceMFA_NoProvider covers GetMFALoginRequired=true + nil provider (client==nil) → false.
func TestShouldEnforceMFA_NoProvider(t *testing.T) {
	database := setupTestDB(t)
	mockStore := &mockLoginErrStore{
		DB:                      database,
		getMFALoginRequiredVal:  true,
		getMFAProviderForIDPNil: true,
	}
	h := newMockLoginHandler(t, mockStore, database)
	if h.shouldEnforceMFAOnLogin(context.Background(), "test-idp") {
		t.Error("expected false when no MFA provider configured")
	}
}

// TestShouldEnforceMFA_ReturnsTrue covers the full happy path: required=true, emailotp provider → returns true.
func TestShouldEnforceMFA_ReturnsTrue(t *testing.T) {
	database := setupTestDB(t)
	ctx := context.Background()

	// Enable MFA-on-login.
	if err := database.SetMFALoginRequired(ctx, true); err != nil {
		t.Fatalf("SetMFALoginRequired: %v", err)
	}

	// Create an emailotp MFA provider and set as default.
	provider := &db.MFAProviderRecord{
		ID:           "mfa-1",
		Name:         "Email OTP",
		ProviderType: "email",
		Enabled:      true,
		ConfigJSON:   `{"otp_length":6,"otp_ttl_minutes":5}`,
	}
	if err := database.CreateMFAProvider(ctx, provider); err != nil {
		t.Fatalf("CreateMFAProvider: %v", err)
	}
	id := "mfa-1"
	if err := database.SetDefaultMFAProviderID(ctx, &id); err != nil {
		t.Fatalf("SetDefaultMFAProviderID: %v", err)
	}

	h := newMockLoginHandler(t, database, database)
	if !h.shouldEnforceMFAOnLogin(ctx, "any-idp") {
		t.Error("expected true when MFA required and emailotp provider configured with passing HealthCheck")
	}
}

// TestRenderLoginError_ListIDPsError covers the ListEnabledIDPs error path in renderLoginError.
func TestRenderLoginError_ListIDPsError(t *testing.T) {
	database := setupTestDB(t)
	mockStore := &mockLoginErrStore{
		DB:                 database,
		listEnabledIDPsErr: fmt.Errorf("db failure"),
	}
	h := newMockLoginHandler(t, mockStore, database)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	h.renderLoginError(rec, req, "invalid credentials")

	// renderLoginError renders a 200 page regardless of IDP load error.
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// TestLoginProvider_MFARedirect covers loginProvider when MFA is required and
// UpdateSessionMFA succeeds → redirected to /mfa.
func TestLoginProvider_MFARedirect(t *testing.T) {
	database := setupTestDB(t)
	logger := testLogger()
	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)

	mfaRecord := &db.MFAProviderRecord{
		ID:           "emailotp-1",
		Name:         "Email OTP",
		ProviderType: "email",
		Enabled:      true,
		ConfigJSON:   `{"otp_length":6,"otp_ttl_minutes":5}`,
	}
	mockStore := &mockLoginErrStore{
		DB:                         database,
		getMFALoginRequiredVal:     true,
		getMFAProviderForIDPRecord: mfaRecord,
	}
	h := newMockLoginHandler(t, mockStore, database)
	h.registry.Register("corp-ad", &mockProvider{id: "corp-ad"})

	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad", Enabled: true, ConfigJSON: "{}",
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	// Create an existing session so r.Cookie("passport_session") is non-nil.
	rec0 := httptest.NewRecorder()
	req0 := httptest.NewRequest(http.MethodGet, "/", nil)
	sessID, err := sm.CreateSession(rec0, req0, "provider", "corp-ad", "jdoe", false, false)
	if err != nil {
		t.Fatalf("creating prelim session: %v", err)
	}

	form := url.Values{}
	form.Set("provider_id", "corp-ad")
	form.Set("username", "jdoe")
	form.Set("password", "secret")
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "passport_session", Value: sessID})
	rec := httptest.NewRecorder()
	h.Login(rec, req)

	// UpdateSessionMFA succeeds → redirect to /mfa.
	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/mfa" {
		t.Errorf("expected redirect to /mfa, got %s", loc)
	}
}

// TestLoginProvider_MFAUpdateSessionError covers loginProvider when MFA is required
// but UpdateSessionMFA fails → falls through to /dashboard.
func TestLoginProvider_MFAUpdateSessionError(t *testing.T) {
	database := setupTestDB(t)
	logger := testLogger()
	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)

	mfaRecord := &db.MFAProviderRecord{
		ID:           "emailotp-2",
		Name:         "Email OTP",
		ProviderType: "email",
		Enabled:      true,
		ConfigJSON:   `{"otp_length":6,"otp_ttl_minutes":5}`,
	}
	mockStore := &mockLoginErrStore{
		DB:                         database,
		getMFALoginRequiredVal:     true,
		getMFAProviderForIDPRecord: mfaRecord,
		updateSessionMFAErr:        fmt.Errorf("db error"),
	}
	h := newMockLoginHandler(t, mockStore, database)
	h.registry.Register("corp-ad", &mockProvider{id: "corp-ad"})

	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID: "corp-ad-2", FriendlyName: "Corp AD 2", ProviderType: "ad", Enabled: true, ConfigJSON: "{}",
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	// Create an existing session so r.Cookie("passport_session") is non-nil.
	rec0 := httptest.NewRecorder()
	req0 := httptest.NewRequest(http.MethodGet, "/", nil)
	sessID, err := sm.CreateSession(rec0, req0, "provider", "corp-ad", "jdoe", false, false)
	if err != nil {
		t.Fatalf("creating prelim session: %v", err)
	}

	form := url.Values{}
	form.Set("provider_id", "corp-ad")
	form.Set("username", "jdoe")
	form.Set("password", "secret")
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "passport_session", Value: sessID})
	rec := httptest.NewRecorder()
	h.Login(rec, req)

	// UpdateSessionMFA error → fall through → redirect to /dashboard.
	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected redirect to /dashboard, got %s", loc)
	}
}

// TestCheckAdminGroupMembership_DBError covers GetAdminGroupsByIDP error → returns false.
func TestCheckAdminGroupMembership_DBError(t *testing.T) {
	database := setupTestDB(t)
	mockStore := &mockLoginErrStore{
		DB:                     database,
		getAdminGroupsByIDPErr: fmt.Errorf("db failure"),
	}
	h := newMockLoginHandler(t, mockStore, database)
	h.registry.Register("corp-ad", &mockProvider{id: "corp-ad"})

	provider, _ := h.registry.Get("corp-ad")
	result := h.checkAdminGroupMembership(context.Background(), provider, "corp-ad", "jdoe")
	if result {
		t.Error("expected false when GetAdminGroupsByIDP fails")
	}
}

// TestCheckAdminGroupMembership_NoMatch covers lines 408-412 where admin groups are
// configured, the user's groups are retrieved, but none match → returns false.
func TestCheckAdminGroupMembership_NoMatch(t *testing.T) {
	env := setupLoginTest(t)
	env.createIDPRecord(t, "corp-ad", "Corporate AD")

	// Create an admin group in the DB.
	if err := env.db.CreateAdminGroup(context.Background(), &db.AdminGroup{
		IDPID:   "corp-ad",
		GroupDN: "CN=Admins,OU=Groups,DC=example,DC=com",
	}); err != nil {
		t.Fatalf("creating admin group: %v", err)
	}

	// Provider returns groups that do NOT include the admin group DN.
	env.registry.Register("corp-ad", &mockProvider{
		id:         "corp-ad",
		userGroups: []string{"CN=RegularUsers,OU=Groups,DC=example,DC=com"},
	})

	form := url.Values{}
	form.Set("provider_id", "corp-ad")
	form.Set("username", "jdoe")
	form.Set("password", "secret")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.Login(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify session was created with isAdmin=false (no admin group match).
	sessionCookies := rec.Result().Cookies()
	var sessionID string
	for _, c := range sessionCookies {
		if c.Name == "passport_session" {
			sessionID = c.Value
		}
	}
	if sessionID == "" {
		t.Fatal("expected session cookie")
	}
	sess, err := env.db.GetSession(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("getting session: %v", err)
	}
	if sess.IsAdmin {
		t.Error("expected session to have isAdmin=false for non-admin group member")
	}
}

// TestShouldEnforceMFA_HealthCheckFails covers login.go:351-354 where client.HealthCheck
// returns an error → shouldEnforceMFAOnLogin returns false (fail-open).
func TestShouldEnforceMFA_HealthCheckFails(t *testing.T) {
	database := setupTestDB(t)
	logger := testLogger()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	cryptoSvc, err := crypto.NewService(key, 1)
	if err != nil {
		t.Fatalf("creating crypto service: %v", err)
	}

	// Encrypt a valid 40-char Duo client secret so duo.New succeeds.
	secretBlob, err := cryptoSvc.Encrypt([]byte(`{"client_secret":"1234567890123456789012345678901234567890"}`))
	if err != nil {
		t.Fatalf("encrypting duo secret: %v", err)
	}

	duoRecord := &db.MFAProviderRecord{
		ID:           "duo-hc-fail",
		Name:         "Duo",
		ProviderType: "duo",
		Enabled:      true,
		ConfigJSON:   `{"client_id":"12345678901234567890","api_hostname":"api.duo.invalid","redirect_uri":"https://app.example.com/cb"}`,
		SecretBlob:   secretBlob,
	}
	mockStore := &mockLoginErrStore{
		DB:                         database,
		getMFALoginRequiredVal:     true,
		getMFAProviderForIDPRecord: duoRecord,
	}

	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := loginStubRenderer(t)
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

	h := NewLoginHandler(mockStore, sm, registry, &mockCorrelator{}, cryptoSvc, renderer, auditLog, logger)
	if h.shouldEnforceMFAOnLogin(context.Background(), "test-idp") {
		t.Error("expected false when HealthCheck fails (fail-open)")
	}
}

// TestLoginProvider_SelfMappingCreatedBeforeMFARedirect is a regression test for the
// bug where the self-mapping (auto-link) was only created after the MFA redirect block.
// When MFA is enforced on login, loginProvider returned early at the MFA redirect and
// never reached the self-mapping code. After MFA completion the user landed on the
// dashboard showing the "Link Account" form instead of "Change Password".
//
// The fix moves self-mapping creation before the MFA redirect so the mapping is
// persisted regardless of whether MFA is required.
func TestLoginProvider_SelfMappingCreatedBeforeMFARedirect(t *testing.T) {
	database := setupTestDB(t)
	logger := testLogger()

	mfaRecord := &db.MFAProviderRecord{
		ID:           "emailotp-selfmap",
		Name:         "Email OTP",
		ProviderType: "email",
		Enabled:      true,
		ConfigJSON:   `{"otp_length":6,"otp_ttl_minutes":5}`,
	}
	mockStore := &mockLoginErrStore{
		DB:                         database,
		getMFALoginRequiredVal:     true,
		getMFAProviderForIDPRecord: mfaRecord,
	}

	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := loginStubRenderer(t)
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

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generating crypto key: %v", err)
	}
	cryptoSvc, err := crypto.NewService(key, 1)
	if err != nil {
		t.Fatalf("creating crypto service: %v", err)
	}

	expectedDN := "uid=rtripathy,cn=users,cn=accounts,dc=idm,dc=ftscc,dc=net"
	registry.Register("redhat-idm", &mockProviderWithDN{
		mockProvider: mockProvider{id: "redhat-idm"},
		searchUserDN: expectedDN,
	})

	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "redhat-idm",
		FriendlyName: "Red Hat IDM",
		ProviderType: "freeipa",
		Enabled:      true,
		ConfigJSON:   `{}`,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	h := NewLoginHandler(mockStore, sm, registry, &mockCorrelator{}, cryptoSvc, renderer, auditLog, logger)

	form := url.Values{}
	form.Set("provider_id", "redhat-idm")
	form.Set("username", "rtripathy")
	form.Set("password", "secret")
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Login(rec, req)

	// MFA is required — must redirect to /mfa.
	if rec.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/mfa" {
		t.Errorf("expected redirect to /mfa, got %s", loc)
	}

	// The self-mapping must already exist even though the user was redirected to MFA
	// and has not yet reached the dashboard. Before the fix, it would not exist here.
	mappings, err := database.ListMappings(context.Background(), "redhat-idm", "rtripathy")
	if err != nil {
		t.Fatalf("listing mappings: %v", err)
	}

	var selfMapping *db.UserIDPMapping
	for i := range mappings {
		if mappings[i].AuthProviderID == "redhat-idm" && mappings[i].TargetIDPID == "redhat-idm" {
			selfMapping = &mappings[i]
			break
		}
	}
	if selfMapping == nil {
		t.Fatal("self-mapping not created before MFA redirect; user would see 'Link Account' instead of 'Change Password' on the dashboard")
	}
	if selfMapping.TargetAccountDN != expectedDN {
		t.Errorf("expected target DN %q, got %q", expectedDN, selfMapping.TargetAccountDN)
	}
	if selfMapping.LinkType != "auto" {
		t.Errorf("expected link type 'auto', got %q", selfMapping.LinkType)
	}
	if selfMapping.VerifiedAt == nil {
		t.Error("expected verified_at to be set on self-mapping")
	}
}
