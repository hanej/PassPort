package handler

import (
	"context"
	"encoding/json"
	"errors"
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

// mockPolicyProvider is a provider that can also report the directory's password
// rules, exercising the idp.PasswordPolicyReader branch of pageData.
type mockPolicyProvider struct {
	*mockProvider
	policy    idp.PasswordPolicy
	policyErr error
}

func (m *mockPolicyProvider) ResolvePasswordPolicy(_ context.Context, _ string) (idp.PasswordPolicy, error) {
	return m.policy, m.policyErr
}

func adChangeStubRenderer(t *testing.T) *Renderer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	pages := make(map[string]*template.Template)
	pages["ad_force_password_change.html"] = template.Must(template.New("ad_force_password_change.html").Parse(
		`{{define "base"}}ad change page|hint={{index .Data "ComplexityHint"}}|policy={{with index .Data "PasswordPolicy"}}{{.MinLength}}{{end}}|flash={{with .Flash}}{{index . "message"}}{{end}}{{end}}`))
	pages["error.html"] = template.Must(template.New("error.html").Parse(
		`{{define "base"}}error page: {{index .Data "ErrorMessage"}}{{end}}`))

	return &Renderer{pages: pages, logger: logger}
}

type adChangeTestEnv struct {
	db       *db.DB
	sm       *auth.SessionManager
	handler  *ADChangePasswordHandler
	registry *idp.Registry
}

func setupADChangeTest(t *testing.T) *adChangeTestEnv {
	t.Helper()

	database := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	registry := idp.NewRegistry(logger)

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

	h := NewADChangePasswordHandler(sm, adChangeStubRenderer(t), auditLog, logger, registry, database, cryptoSvc)

	return &adChangeTestEnv{db: database, sm: sm, handler: h, registry: registry}
}

// createIDPWithHint stores an AD provider whose config carries a complexity hint.
func (env *adChangeTestEnv) createIDPWithHint(t *testing.T, id, hint string) {
	t.Helper()
	cfg := idp.Config{Endpoint: "ldap.example.com:389", PasswordComplexityHint: hint}
	configJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshalling config: %v", err)
	}
	rec := &db.IdentityProviderRecord{
		ID:           id,
		FriendlyName: "Corp AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(configJSON),
	}
	if err := env.db.CreateIDP(context.Background(), rec); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}
}

func (env *adChangeTestEnv) session(t *testing.T, providerID, username string) ([]*http.Cookie, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	id, err := env.sm.CreateSession(rec, req, "provider", providerID, username, false, true)
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}
	return rec.Result().Cookies(), id
}

func (env *adChangeTestEnv) serve(t *testing.T, h http.HandlerFunc, method, path string, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
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

	rec := httptest.NewRecorder()
	env.sm.Middleware(h).ServeHTTP(rec, req)
	return rec
}

func changeForm(current, next, confirm string) string {
	form := url.Values{}
	form.Set("current_password", current)
	form.Set("new_password", next)
	form.Set("confirm_password", confirm)
	return form.Encode()
}

func TestADChangePassword_ShowRendersHintAndPolicy(t *testing.T) {
	env := setupADChangeTest(t)
	env.createIDPWithHint(t, "corp-ad", "Twelve characters minimum.")
	env.registry.Register("corp-ad", &mockPolicyProvider{
		mockProvider: &mockProvider{id: "corp-ad", providerType: idp.ProviderTypeAD},
		policy:       idp.PasswordPolicy{MinLength: 14, ComplexityEnabled: true},
	})
	cookies, _ := env.session(t, "corp-ad", "alice")

	rec := env.serve(t, env.handler.ShowChangePassword, http.MethodGet, "/ad-change-password", cookies, "")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "hint=Twelve characters minimum.") {
		t.Errorf("complexity hint missing from page: %s", body)
	}
	if !strings.Contains(body, "policy=14") {
		t.Errorf("directory policy missing from page: %s", body)
	}
}

// A directory that cannot report its policy must still render the form: the
// directory stays the authority, the client-side rules are only a convenience.
func TestADChangePassword_ShowPolicyErrorStillRenders(t *testing.T) {
	env := setupADChangeTest(t)
	env.createIDPWithHint(t, "corp-ad", "Be creative.")
	env.registry.Register("corp-ad", &mockPolicyProvider{
		mockProvider: &mockProvider{id: "corp-ad", providerType: idp.ProviderTypeAD},
		policyErr:    errors.New("insufficient access rights"),
	})
	cookies, _ := env.session(t, "corp-ad", "alice")

	rec := env.serve(t, env.handler.ShowChangePassword, http.MethodGet, "/ad-change-password", cookies, "")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "policy=|") {
		t.Errorf("expected empty policy, got: %s", body)
	}
}

// A provider that is not a PasswordPolicyReader, and an IDP row that cannot be
// read, both degrade to a plain form rather than failing.
func TestADChangePassword_ShowWithoutPolicyReaderOrIDPRow(t *testing.T) {
	env := setupADChangeTest(t)
	env.registry.Register("corp-ad", &mockProvider{id: "corp-ad", providerType: idp.ProviderTypeAD})
	cookies, _ := env.session(t, "corp-ad", "alice")

	rec := env.serve(t, env.handler.ShowChangePassword, http.MethodGet, "/ad-change-password", cookies, "")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "hint=|") {
		t.Errorf("expected empty hint, got: %s", body)
	}
}

func TestADChangePassword_ShowUnregisteredProvider(t *testing.T) {
	env := setupADChangeTest(t)
	env.createIDPWithHint(t, "corp-ad", "Twelve characters minimum.")
	cookies, _ := env.session(t, "corp-ad", "alice")

	rec := env.serve(t, env.handler.ShowChangePassword, http.MethodGet, "/ad-change-password", cookies, "")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "hint=Twelve characters minimum.") {
		t.Errorf("expected hint even without a registered provider, got: %s", body)
	}
}

// An IDP whose config_json is not valid JSON must not take the page down.
func TestADChangePassword_ShowMalformedConfigJSON(t *testing.T) {
	env := setupADChangeTest(t)
	rec := &db.IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad",
		Enabled: true, ConfigJSON: "{not json",
	}
	if err := env.db.CreateIDP(context.Background(), rec); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}
	cookies, _ := env.session(t, "corp-ad", "alice")

	res := env.serve(t, env.handler.ShowChangePassword, http.MethodGet, "/ad-change-password", cookies, "")

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.Code)
	}
	if body := res.Body.String(); !strings.Contains(body, "hint=|") {
		t.Errorf("expected empty hint, got: %s", body)
	}
}

func TestADChangePassword_Success(t *testing.T) {
	env := setupADChangeTest(t)
	env.createIDPWithHint(t, "corp-ad", "Twelve characters minimum.")
	env.registry.Register("corp-ad", &mockProvider{id: "corp-ad", providerType: idp.ProviderTypeAD})
	cookies, sessionID := env.session(t, "corp-ad", "alice")

	rec := env.serve(t, env.handler.ChangePassword, http.MethodPost, "/ad-change-password", cookies,
		changeForm("OldPass1!", "BrandNewPass1!", "BrandNewPass1!"))

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected redirect to /dashboard, got %q", loc)
	}

	// The forced-change flag must be cleared or the user is trapped on this page.
	sess, err := env.db.GetSession(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("getting session: %v", err)
	}
	if sess.MustChangePassword {
		t.Error("expected must_change_password to be cleared")
	}

	entries, _, err := env.db.ListAudit(context.Background(), db.AuditFilter{Limit: 10})
	if err != nil {
		t.Fatalf("listing audit log: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action == audit.ActionPasswordChange && e.Result == audit.ResultSuccess {
			found = true
		}
	}
	if !found {
		t.Error("expected a successful password_change audit entry")
	}
}

func TestADChangePassword_NoSession(t *testing.T) {
	env := setupADChangeTest(t)

	req := httptest.NewRequest(http.MethodPost, "/ad-change-password",
		strings.NewReader(changeForm("a", "b", "b")))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.ChangePassword(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestADChangePassword_ValidationFailures(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantMsg string
	}{
		{"empty new password", changeForm("OldPass1!", "", ""), "New password cannot be empty."},
		{"mismatch", changeForm("OldPass1!", "NewPass1!", "Different1!"), "Passwords do not match."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := setupADChangeTest(t)
			env.createIDPWithHint(t, "corp-ad", "Twelve characters minimum.")
			env.registry.Register("corp-ad", &mockProvider{id: "corp-ad", providerType: idp.ProviderTypeAD})
			cookies, _ := env.session(t, "corp-ad", "alice")

			rec := env.serve(t, env.handler.ChangePassword, http.MethodPost, "/ad-change-password", cookies, tt.body)

			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", rec.Code)
			}
			if body := rec.Body.String(); !strings.Contains(body, tt.wantMsg) {
				t.Errorf("expected %q, got: %s", tt.wantMsg, body)
			}
		})
	}
}

func TestADChangePassword_ProviderNotRegistered(t *testing.T) {
	env := setupADChangeTest(t)
	env.createIDPWithHint(t, "corp-ad", "")
	cookies, _ := env.session(t, "corp-ad", "alice")

	rec := env.serve(t, env.handler.ChangePassword, http.MethodPost, "/ad-change-password", cookies,
		changeForm("OldPass1!", "BrandNewPass1!", "BrandNewPass1!"))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

// Each directory failure must reach the user as its own explanation; a generic
// "try again" hides a locked account or a policy the user can actually satisfy.
func TestADChangePassword_DirectoryErrorMessages(t *testing.T) {
	tests := []struct {
		name    string
		hint    string
		err     error
		wantMsg string
	}{
		{
			name:    "policy violation appends the configured hint",
			hint:    "Twelve characters minimum.",
			err:     idp.ErrPasswordPolicy,
			wantMsg: "complexity, history, or minimum age requirements. Twelve characters minimum.",
		},
		{
			name:    "policy violation without a hint",
			err:     idp.ErrPasswordPolicy,
			wantMsg: "does not meet your organization&#39;s complexity",
		},
		{
			name:    "wrong current password",
			err:     errors.New("current password is incorrect"),
			wantMsg: "Current password is incorrect.",
		},
		{
			name:    "locked account",
			err:     idp.ErrAccountLocked,
			wantMsg: "Your account is locked.",
		},
		{
			name:    "disabled account",
			err:     idp.ErrAccountDisabled,
			wantMsg: "Your account is disabled.",
		},
		{
			name:    "unclassified failure",
			err:     errors.New("connection refused"),
			wantMsg: "Password change failed.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := setupADChangeTest(t)
			env.createIDPWithHint(t, "corp-ad", tt.hint)
			env.registry.Register("corp-ad", &mockProvider{
				id: "corp-ad", providerType: idp.ProviderTypeAD, changePassErr: tt.err,
			})
			cookies, _ := env.session(t, "corp-ad", "alice")

			rec := env.serve(t, env.handler.ChangePassword, http.MethodPost, "/ad-change-password", cookies,
				changeForm("WrongPass1!", "BrandNewPass1!", "BrandNewPass1!"))

			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", rec.Code)
			}
			if body := rec.Body.String(); !strings.Contains(body, tt.wantMsg) {
				t.Errorf("expected %q, got: %s", tt.wantMsg, body)
			}
		})
	}
}

// createIDPWithConfig stores an AD provider with an arbitrary config.
func (env *adChangeTestEnv) createIDPWithConfig(t *testing.T, id string, cfg idp.Config) {
	t.Helper()
	configJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshalling config: %v", err)
	}
	rec := &db.IdentityProviderRecord{
		ID:           id,
		FriendlyName: "Corp AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(configJSON),
	}
	if err := env.db.CreateIDP(context.Background(), rec); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}
}

// An admin who turns the checklist off must not have it read from the directory
// at all, so the page costs no extra LDAP round trip either.
func TestADChangePassword_DiscoveredPolicyCanBeHidden(t *testing.T) {
	env := setupADChangeTest(t)
	env.createIDPWithConfig(t, "corp-ad", idp.Config{
		PasswordComplexityHint:       "Ask the helpdesk.",
		HideDiscoveredPasswordPolicy: true,
	})
	provider := &mockPolicyProvider{
		mockProvider: &mockProvider{id: "corp-ad", providerType: idp.ProviderTypeAD},
		policy:       idp.PasswordPolicy{MinLength: 14},
	}
	env.registry.Register("corp-ad", provider)
	cookies, _ := env.session(t, "corp-ad", "alice")

	rec := env.serve(t, env.handler.ShowChangePassword, http.MethodGet, "/ad-change-password", cookies, "")

	body := rec.Body.String()
	if !strings.Contains(body, "hint=Ask the helpdesk.") {
		t.Errorf("the admin's own hint should still render: %s", body)
	}
	if !strings.Contains(body, "policy=|") {
		t.Errorf("expected no discovered policy, got: %s", body)
	}
}
