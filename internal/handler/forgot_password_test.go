package handler

import (
	"context"
	"html/template"
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

// forgotStubRenderer creates a Renderer with stubs for forgot/reset pages.
func forgotStubRenderer(t *testing.T) *Renderer {
	t.Helper()
	funcMap := template.FuncMap{
		"add":          func(a, b int) int { return a + b },
		"subtract":     func(a, b int) int { return a - b },
		"pages":        func(n int) []int { return nil },
		"markdownHTML": func(s string) template.HTML { return template.HTML(s) },
		"contains":     strings.Contains,
		"hexToRGB":     func(s string) string { return "" },
		"darkenHex":    func(s string, f float64) string { return s },
		"branding":     func() *db.BrandingConfig { return &db.BrandingConfig{} },
	}
	pages := make(map[string]*template.Template)
	pages["forgot_password.html"] = template.Must(
		template.New("forgot_password.html").Funcs(funcMap).Parse(`{{define "base"}}forgot {{if .Flash}}{{.Flash.message}}{{end}} {{range .Data.IDPs}}{{.ID}}{{end}}{{end}}`))
	pages["reset_password.html"] = template.Must(
		template.New("reset_password.html").Funcs(funcMap).Parse(`{{define "base"}}reset {{if .Flash}}{{.Flash.message}}{{end}}{{end}}`))
	pages["error.html"] = template.Must(
		template.New("error.html").Funcs(funcMap).Parse(`{{define "base"}}error page{{end}}`))

	return &Renderer{pages: pages, logger: testLogger()}
}

// mockProviderSearchFail returns an error from every SearchUser call.
type mockProviderSearchFail struct {
	mockProvider
}

func (m *mockProviderSearchFail) SearchUser(_ context.Context, _, _ string) (string, error) {
	return "", errUserNotFound
}

var errUserNotFound = &searchErr{"user not found"}

type searchErr struct{ msg string }

func (e *searchErr) Error() string { return e.msg }

// mockProviderResetFail is a provider that succeeds on SearchUser but fails ResetPassword.
type mockProviderResetFail struct {
	mockProviderWithDN
}

func (m *mockProviderResetFail) ResetPassword(_ context.Context, _, _ string) error {
	return errResetFailed
}

var errResetFailed = &searchErr{"ldap reset failed"}

// mockProviderChangeFail succeeds on ResetPassword but fails ChangePassword.
type mockProviderChangeFail struct {
	mockProviderWithDN
}

func (m *mockProviderChangeFail) ChangePassword(_ context.Context, _, _, _ string) error {
	return errChangeFailed
}

var errChangeFailed = &searchErr{"policy violation"}

type forgotTestEnv struct {
	db       *db.DB
	sm       *auth.SessionManager
	handler  *ForgotPasswordHandler
	registry *idp.Registry
}

func setupForgotTest(t *testing.T) *forgotTestEnv {
	t.Helper()

	database := setupTestDB(t)
	logger := testLogger()

	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := forgotStubRenderer(t)
	registry := idp.NewRegistry(logger)

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

	h := NewForgotPasswordHandler(database, registry, sm, renderer, auditLog, logger)

	return &forgotTestEnv{
		db:       database,
		sm:       sm,
		handler:  h,
		registry: registry,
	}
}

func (env *forgotTestEnv) createIDP(t *testing.T, id string) {
	t.Helper()
	rec := &db.IdentityProviderRecord{
		ID:           id,
		FriendlyName: id + " provider",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   `{"endpoint":"ldap.example.com:636","protocol":"ldaps","base_dn":"dc=example,dc=com","password_length":12,"password_allow_uppercase":true,"password_allow_lowercase":true,"password_allow_digits":true}`,
	}
	if err := env.db.CreateIDP(context.Background(), rec); err != nil {
		t.Fatalf("creating IDP %q: %v", id, err)
	}
}

func (env *forgotTestEnv) createResetSession(t *testing.T, idpID, username string) []*http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := env.sm.CreateSession(w, r, "reset", idpID, username, false, false)
	if err != nil {
		t.Fatalf("creating reset session: %v", err)
	}
	return w.Result().Cookies()
}

func (env *forgotTestEnv) serveWithSession(t *testing.T, handler http.HandlerFunc, method, path string, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
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

// ---- ShowForm tests ----

func TestForgotPasswordShowForm(t *testing.T) {
	env := setupForgotTest(t)
	env.createIDP(t, "corp-ad")

	req := httptest.NewRequest(http.MethodGet, "/forgot-password", nil)
	rec := httptest.NewRecorder()
	env.handler.ShowForm(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "corp-ad") {
		t.Errorf("expected IDP ID in response, got: %s", rec.Body.String())
	}
}

// ---- Submit tests ----

func TestForgotPasswordSubmit_MissingFields(t *testing.T) {
	env := setupForgotTest(t)

	form := url.Values{}
	// Leave idp_id and username empty.
	req := httptest.NewRequest(http.MethodPost, "/forgot-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.Submit(rec, req)

	// Should re-render form with error (200 OK, not redirect).
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Please select") {
		t.Errorf("expected error message in response, got: %s", rec.Body.String())
	}
}

func TestForgotPasswordSubmit_LocalIDPRejected(t *testing.T) {
	env := setupForgotTest(t)

	form := url.Values{}
	form.Set("idp_id", "local")
	form.Set("username", "admin")
	req := httptest.NewRequest(http.MethodPost, "/forgot-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.Submit(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for form re-render, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not available for local") {
		t.Errorf("expected local admin error, got: %s", rec.Body.String())
	}
}

func TestForgotPasswordSubmit_ProviderNotFound(t *testing.T) {
	env := setupForgotTest(t)

	form := url.Values{}
	form.Set("idp_id", "nonexistent")
	form.Set("username", "jdoe")
	req := httptest.NewRequest(http.MethodPost, "/forgot-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.Submit(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not available") {
		t.Errorf("expected error about provider not available, got: %s", rec.Body.String())
	}
}

func TestForgotPasswordSubmit_UserNotFound(t *testing.T) {
	env := setupForgotTest(t)
	env.createIDP(t, "corp-ad")
	env.registry.Register("corp-ad", &mockProviderSearchFail{mockProvider: mockProvider{id: "corp-ad"}})

	form := url.Values{}
	form.Set("idp_id", "corp-ad")
	form.Set("username", "unknown-user")
	req := httptest.NewRequest(http.MethodPost, "/forgot-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.Submit(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for form re-render, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "User not found") {
		t.Errorf("expected 'User not found' in response, got: %s", rec.Body.String())
	}
}

func TestForgotPasswordSubmit_SuccessNoMFA(t *testing.T) {
	env := setupForgotTest(t)
	env.createIDP(t, "corp-ad")
	env.registry.Register("corp-ad", &mockProvider{id: "corp-ad"}) // SearchUser returns "", nil

	form := url.Values{}
	form.Set("idp_id", "corp-ad")
	form.Set("username", "jdoe")
	req := httptest.NewRequest(http.MethodPost, "/forgot-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.Submit(rec, req)

	// No MFA configured → redirect to /reset-password.
	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect 302, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/reset-password" {
		t.Errorf("expected redirect to /reset-password, got %s", loc)
	}
}

// ---- ShowReset tests ----

func TestShowReset_NoSession(t *testing.T) {
	env := setupForgotTest(t)

	req := httptest.NewRequest(http.MethodGet, "/reset-password", nil)
	rec := httptest.NewRecorder()
	env.handler.ShowReset(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected redirect to /login, got %s", loc)
	}
}

func TestShowReset_WrongUserType(t *testing.T) {
	env := setupForgotTest(t)

	// Create a regular (non-reset) session.
	cookies := env.createSessionCookies(t, "local", "", "admin", true)
	rec := env.serveWithSession(t, env.handler.ShowReset, http.MethodGet, "/reset-password", cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected redirect to /login, got %s", loc)
	}
}

func TestShowReset_ValidResetSession(t *testing.T) {
	env := setupForgotTest(t)
	env.createIDP(t, "corp-ad")

	// Create a reset session.
	cookies := env.createResetSession(t, "corp-ad", "jdoe")
	rec := env.serveWithSession(t, env.handler.ShowReset, http.MethodGet, "/reset-password", cookies, "")

	// No MFA configured → render the form (200 OK).
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func (env *forgotTestEnv) createSessionCookies(t *testing.T, userType, providerID, username string, isAdmin bool) []*http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := env.sm.CreateSession(w, r, userType, providerID, username, isAdmin, false)
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}
	return w.Result().Cookies()
}

// ---- ResetPassword tests ----

func TestResetPassword_NoSession(t *testing.T) {
	env := setupForgotTest(t)

	req := httptest.NewRequest(http.MethodPost, "/reset-password", nil)
	rec := httptest.NewRecorder()
	env.handler.ResetPassword(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
}

func TestResetPassword_EmptyPassword(t *testing.T) {
	env := setupForgotTest(t)
	env.createIDP(t, "corp-ad")

	cookies := env.createResetSession(t, "corp-ad", "jdoe")

	form := url.Values{}
	form.Set("new_password", "")
	form.Set("confirm_password", "")

	rec := env.serveWithSession(t, env.handler.ResetPassword, http.MethodPost, "/reset-password", cookies, form.Encode())

	// Should redirect back with error flash.
	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestResetPassword_PasswordMismatch(t *testing.T) {
	env := setupForgotTest(t)
	env.createIDP(t, "corp-ad")

	cookies := env.createResetSession(t, "corp-ad", "jdoe")

	form := url.Values{}
	form.Set("new_password", "NewPass1!")
	form.Set("confirm_password", "DifferentPass1!")

	rec := env.serveWithSession(t, env.handler.ResetPassword, http.MethodPost, "/reset-password", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
}

func TestResetPassword_ProviderNotFound(t *testing.T) {
	env := setupForgotTest(t)
	env.createIDP(t, "corp-ad")
	// Don't register provider in registry.

	cookies := env.createResetSession(t, "corp-ad", "jdoe")

	form := url.Values{}
	form.Set("new_password", "NewPass1!")
	form.Set("confirm_password", "NewPass1!")

	rec := env.serveWithSession(t, env.handler.ResetPassword, http.MethodPost, "/reset-password", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/reset-password" {
		t.Errorf("expected redirect back to /reset-password, got %s", loc)
	}
}

func TestResetPassword_UserDNNotFound(t *testing.T) {
	env := setupForgotTest(t)
	env.createIDP(t, "corp-ad")
	env.registry.Register("corp-ad", &mockProviderSearchFail{mockProvider: mockProvider{id: "corp-ad"}})

	cookies := env.createResetSession(t, "corp-ad", "jdoe")

	form := url.Values{}
	form.Set("new_password", "NewPass1!")
	form.Set("confirm_password", "NewPass1!")

	rec := env.serveWithSession(t, env.handler.ResetPassword, http.MethodPost, "/reset-password", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
}

func TestResetPassword_ResetFails(t *testing.T) {
	env := setupForgotTest(t)
	env.createIDP(t, "corp-ad")
	env.registry.Register("corp-ad", &mockProviderResetFail{
		mockProviderWithDN: mockProviderWithDN{
			mockProvider: mockProvider{id: "corp-ad"},
			searchUserDN: "CN=jdoe,DC=example,DC=com",
		},
	})

	cookies := env.createResetSession(t, "corp-ad", "jdoe")

	form := url.Values{}
	form.Set("new_password", "NewPass1!")
	form.Set("confirm_password", "NewPass1!")

	rec := env.serveWithSession(t, env.handler.ResetPassword, http.MethodPost, "/reset-password", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
}

func TestResetPassword_ChangeFails(t *testing.T) {
	env := setupForgotTest(t)
	env.createIDP(t, "corp-ad")
	env.registry.Register("corp-ad", &mockProviderChangeFail{
		mockProviderWithDN: mockProviderWithDN{
			mockProvider: mockProvider{id: "corp-ad"},
			searchUserDN: "CN=jdoe,DC=example,DC=com",
		},
	})

	cookies := env.createResetSession(t, "corp-ad", "jdoe")

	form := url.Values{}
	form.Set("new_password", "NewPass1!")
	form.Set("confirm_password", "NewPass1!")

	rec := env.serveWithSession(t, env.handler.ResetPassword, http.MethodPost, "/reset-password", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
}

func TestResetPassword_Success(t *testing.T) {
	env := setupForgotTest(t)
	env.createIDP(t, "corp-ad")
	env.registry.Register("corp-ad", &mockProviderWithDN{
		mockProvider: mockProvider{id: "corp-ad"},
		searchUserDN: "CN=jdoe,DC=example,DC=com",
	})

	cookies := env.createResetSession(t, "corp-ad", "jdoe")

	form := url.Values{}
	form.Set("new_password", "NewPass1!")
	form.Set("confirm_password", "NewPass1!")

	rec := env.serveWithSession(t, env.handler.ResetPassword, http.MethodPost, "/reset-password", cookies, form.Encode())

	// On success, destroy session + redirect to /login.
	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected redirect to /login, got %s", loc)
	}
}

// mockForgotPwErrStore wraps *db.DB and forces ListEnabledIDPs to fail.
type mockForgotPwErrStore struct {
	*db.DB
	listEnabledIDPsErr         error
	getMFAProviderForIDPErr    error
	getMFAProviderForIDPRecord *db.MFAProviderRecord
}

func (m *mockForgotPwErrStore) ListEnabledIDPs(ctx context.Context) ([]db.IdentityProviderRecord, error) {
	if m.listEnabledIDPsErr != nil {
		return nil, m.listEnabledIDPsErr
	}
	return m.DB.ListEnabledIDPs(ctx)
}

func (m *mockForgotPwErrStore) GetMFAProviderForIDP(ctx context.Context, idpID string) (*db.MFAProviderRecord, error) {
	if m.getMFAProviderForIDPErr != nil {
		return nil, m.getMFAProviderForIDPErr
	}
	if m.getMFAProviderForIDPRecord != nil {
		return m.getMFAProviderForIDPRecord, nil
	}
	return m.DB.GetMFAProviderForIDP(ctx, idpID)
}

func newForgotPwMockHandler(t *testing.T, mock *mockForgotPwErrStore) *ForgotPasswordHandler {
	t.Helper()
	logger := testLogger()
	renderer := forgotStubRenderer(t)
	registry := idp.NewRegistry(logger)
	sm := auth.NewSessionManager(mock.DB, 30*time.Minute, false, logger)

	tmpFile, err := os.CreateTemp(t.TempDir(), "audit-*.log")
	if err != nil {
		t.Fatalf("creating temp audit file: %v", err)
	}
	_ = tmpFile.Close()

	auditLog, err := audit.NewLogger(mock.DB, tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("creating audit logger: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })

	return NewForgotPasswordHandler(mock, registry, sm, renderer, auditLog, logger)
}

// TestForgotPasswordShowForm_ListEnabledIDPsError covers the 500 path in ShowForm
// when the store's ListEnabledIDPs call fails.
func TestForgotPasswordShowForm_ListEnabledIDPsError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockForgotPwErrStore{
		DB:                 database,
		listEnabledIDPsErr: &searchErr{"db failure"},
	}
	h := newForgotPwMockHandler(t, mock)

	req := httptest.NewRequest(http.MethodGet, "/forgot-password", nil)
	rec := httptest.NewRecorder()
	h.ShowForm(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when ListEnabledIDPs fails, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "error page") {
		t.Errorf("expected error page content, got: %s", rec.Body.String())
	}
}

// TestShowReset_GetMFAProviderError covers ShowReset returning 500 when GetMFAProviderForIDP fails.
func TestShowReset_GetMFAProviderError(t *testing.T) {
	database := setupTestDB(t)

	mock := &mockForgotPwErrStore{
		DB:                      database,
		getMFAProviderForIDPErr: &searchErr{"mfa lookup failed"},
	}
	h := newForgotPwMockHandler(t, mock)

	// Create a reset session using a SM on the same DB.
	sm := auth.NewSessionManager(database, 30*time.Minute, false, testLogger())
	wCookie := httptest.NewRecorder()
	rCookie := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := sm.CreateSession(wCookie, rCookie, "reset", "corp-ad", "jdoe", false, false); err != nil {
		t.Fatalf("creating session: %v", err)
	}
	cookies := wCookie.Result().Cookies()

	req := httptest.NewRequest(http.MethodGet, "/reset-password", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	sm.Middleware(http.HandlerFunc(h.ShowReset)).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when GetMFAProviderForIDP fails, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestShowReset_MFANotVerified covers the branch: mfaProvider != nil && sess.MFAState != "verified" → redirect.
func TestShowReset_MFANotVerified(t *testing.T) {
	database := setupTestDB(t)

	// Return a non-nil MFA provider (MFA required for this IDP).
	mock := &mockForgotPwErrStore{
		DB: database,
		getMFAProviderForIDPRecord: &db.MFAProviderRecord{
			ID:           "mfa-1",
			Name:         "Email OTP",
			ProviderType: "email",
			Enabled:      true,
			ConfigJSON:   `{"otp_length":6,"otp_ttl_minutes":5}`,
		},
	}
	h := newForgotPwMockHandler(t, mock)

	sm := auth.NewSessionManager(database, 30*time.Minute, false, testLogger())
	wCookie := httptest.NewRecorder()
	rCookie := httptest.NewRequest(http.MethodGet, "/", nil)
	// MFAState defaults to "" (not "verified").
	if _, err := sm.CreateSession(wCookie, rCookie, "reset", "corp-ad", "jdoe", false, false); err != nil {
		t.Fatalf("creating session: %v", err)
	}
	cookies := wCookie.Result().Cookies()

	req := httptest.NewRequest(http.MethodGet, "/reset-password", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	sm.Middleware(http.HandlerFunc(h.ShowReset)).ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 redirect when MFA not verified, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/forgot-password" {
		t.Errorf("expected redirect to /forgot-password, got %q", loc)
	}
}

// TestForgotPasswordRenderFormError_ListIDPsError covers the ListEnabledIDPs error branch in renderFormError.
func TestForgotPasswordRenderFormError_ListIDPsError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockForgotPwErrStore{
		DB:                 database,
		listEnabledIDPsErr: &searchErr{"db failure"},
	}
	h := newForgotPwMockHandler(t, mock)

	req := httptest.NewRequest(http.MethodGet, "/forgot-password", nil)
	rec := httptest.NewRecorder()
	// renderFormError still renders the form page (200) even when IDPs fail to load.
	h.renderFormError(rec, req, "some validation error")

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 from renderFormError, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "forgot") {
		t.Errorf("expected forgot page content, got: %s", rec.Body.String())
	}
}

// TestForgotPasswordSubmit_GetMFAProviderError covers the 500 path in Submit
// when GetMFAProviderForIDP fails after the reset session is created.
func TestForgotPasswordSubmit_GetMFAProviderError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockForgotPwErrStore{
		DB:                      database,
		getMFAProviderForIDPErr: &searchErr{"mfa lookup failed"},
	}
	h := newForgotPwMockHandler(t, mock)
	h.registry.Register("corp-ad", &mockProvider{id: "corp-ad"})
	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad", Enabled: true, ConfigJSON: "{}",
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	form := url.Values{}
	form.Set("idp_id", "corp-ad")
	form.Set("username", "jdoe")
	req := httptest.NewRequest(http.MethodPost, "/forgot-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Submit(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when GetMFAProviderForIDP fails, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestForgotPasswordSubmit_WithMFA covers the Submit path where MFA is configured
// and the user should be redirected to /mfa instead of /reset-password.
func TestForgotPasswordSubmit_WithMFA(t *testing.T) {
	database := setupTestDB(t)
	mfaRecord := &db.MFAProviderRecord{
		ID:           "emailotp-1",
		ProviderType: "emailotp",
		Name:         "Email OTP",
		Enabled:      true,
	}
	mock := &mockForgotPwErrStore{
		DB:                         database,
		getMFAProviderForIDPRecord: mfaRecord,
	}
	h := newForgotPwMockHandler(t, mock)
	h.registry.Register("corp-ad", &mockProvider{id: "corp-ad"})
	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad", Enabled: true, ConfigJSON: "{}",
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	form := url.Values{}
	form.Set("idp_id", "corp-ad")
	form.Set("username", "jdoe")
	req := httptest.NewRequest(http.MethodPost, "/forgot-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Submit(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect 302 to /mfa, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/mfa" {
		t.Errorf("expected redirect to /mfa, got %s", loc)
	}
}

// TestResetPassword_GetMFAProviderForIDPError covers lines 221-225 where
// GetMFAProviderForIDP returns an error in the ResetPassword handler.
func TestResetPassword_GetMFAProviderForIDPError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockForgotPwErrStore{
		DB:                      database,
		getMFAProviderForIDPErr: &searchErr{"mfa lookup failed"},
	}
	h := newForgotPwMockHandler(t, mock)

	sm := auth.NewSessionManager(database, 30*time.Minute, false, testLogger())
	wCookie := httptest.NewRecorder()
	rCookie := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := sm.CreateSession(wCookie, rCookie, "reset", "corp-ad", "jdoe", false, false); err != nil {
		t.Fatalf("creating session: %v", err)
	}
	cookies := wCookie.Result().Cookies()

	form := url.Values{}
	form.Set("new_password", "NewPass1!")
	form.Set("confirm_password", "NewPass1!")
	req := httptest.NewRequest(http.MethodPost, "/reset-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	sm.Middleware(http.HandlerFunc(h.ResetPassword)).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when GetMFAProviderForIDP fails, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestResetPassword_MFARequiredNotVerified covers lines 226-229 where an MFA provider
// is configured but the session MFAState is not "verified" → redirect to /forgot-password.
func TestResetPassword_MFARequiredNotVerified(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockForgotPwErrStore{
		DB: database,
		getMFAProviderForIDPRecord: &db.MFAProviderRecord{
			ID:           "mfa-1",
			Name:         "Email OTP",
			ProviderType: "email",
			Enabled:      true,
			ConfigJSON:   `{"otp_length":6,"otp_ttl_minutes":5}`,
		},
	}
	h := newForgotPwMockHandler(t, mock)

	sm := auth.NewSessionManager(database, 30*time.Minute, false, testLogger())
	wCookie := httptest.NewRecorder()
	rCookie := httptest.NewRequest(http.MethodGet, "/", nil)
	// MFAState defaults to "" (not "verified").
	if _, err := sm.CreateSession(wCookie, rCookie, "reset", "corp-ad", "jdoe", false, false); err != nil {
		t.Fatalf("creating session: %v", err)
	}
	cookies := wCookie.Result().Cookies()

	form := url.Values{}
	form.Set("new_password", "NewPass1!")
	form.Set("confirm_password", "NewPass1!")
	req := httptest.NewRequest(http.MethodPost, "/reset-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	sm.Middleware(http.HandlerFunc(h.ResetPassword)).ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/forgot-password" {
		t.Errorf("expected /forgot-password, got %s", loc)
	}
}

// TestResetPassword_SpecialCharsEnabled covers line 287-289 where cfg.PasswordAllowSpecialChars
// is true, causing pwSpecial to be set from the IDP's configured special-chars string.
func TestResetPassword_SpecialCharsEnabled(t *testing.T) {
	env := setupForgotTest(t)
	// IDP config has special chars enabled.
	if err := env.db.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-ad",
		FriendlyName: "Corp AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   `{"password_length":12,"password_allow_uppercase":true,"password_allow_lowercase":true,"password_allow_digits":true,"password_allow_special_chars":true,"password_special_chars":"!@#"}`,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}
	env.registry.Register("corp-ad", &mockProviderWithDN{
		mockProvider: mockProvider{id: "corp-ad"},
		searchUserDN: "CN=jdoe,DC=example,DC=com",
	})

	cookies := env.createResetSession(t, "corp-ad", "jdoe")
	form := url.Values{}
	form.Set("new_password", "NewPass1!")
	form.Set("confirm_password", "NewPass1!")
	rec := env.serveWithSession(t, env.handler.ResetPassword, http.MethodPost, "/reset-password", cookies, form.Encode())

	// ResetPassword+ChangePassword succeed; CreateSession("flash") fails (DB constraint)
	// → handler redirects to /login via the error path.
	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected /login, got %s", loc)
	}
}

// TestResetPassword_EmptyCharset covers lines 299-303 where GeneratePasswordWithPolicy
// fails because all character classes (upper, lower, digits, special) are disabled.
func TestResetPassword_EmptyCharset(t *testing.T) {
	env := setupForgotTest(t)
	// IDP config disables all character classes — GeneratePasswordWithPolicy will fail.
	if err := env.db.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-ad",
		FriendlyName: "Corp AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   `{"password_length":12,"password_allow_uppercase":false,"password_allow_lowercase":false,"password_allow_digits":false,"password_allow_special_chars":false}`,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}
	env.registry.Register("corp-ad", &mockProviderWithDN{
		mockProvider: mockProvider{id: "corp-ad"},
		searchUserDN: "CN=jdoe,DC=example,DC=com",
	})

	cookies := env.createResetSession(t, "corp-ad", "jdoe")
	form := url.Values{}
	form.Set("new_password", "NewPass1!")
	form.Set("confirm_password", "NewPass1!")
	rec := env.serveWithSession(t, env.handler.ResetPassword, http.MethodPost, "/reset-password", cookies, form.Encode())

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when charset is empty, got %d; body: %s", rec.Code, rec.Body.String())
	}
}
