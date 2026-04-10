package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"mime/multipart"
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
)

type idpTestEnv struct {
	db       *db.DB
	crypto   *crypto.Service
	registry *idp.Registry
	handler  *AdminIDPHandler
	sm       *auth.SessionManager
	audit    *audit.Logger
}

func stubIDPRenderer(t *testing.T) *Renderer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	funcMap := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"pages":    func(n int) []int { return nil },
	}
	pages := make(map[string]*template.Template)
	pages["admin_idp_list.html"] = template.Must(template.New("admin_idp_list.html").Funcs(funcMap).Parse(`{{define "base"}}idp list page{{end}}`))
	pages["admin_idp_form.html"] = template.Must(template.New("admin_idp_form.html").Funcs(funcMap).Parse(`{{define "base"}}idp form page{{end}}`))
	pages["error.html"] = template.Must(template.New("error.html").Funcs(funcMap).Parse(`{{define "base"}}error page{{end}}`))
	return &Renderer{pages: pages, logger: logger}
}

func setupIDPTest(t *testing.T) *idpTestEnv {
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

	registry := idp.NewRegistry(logger)
	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := stubIDPRenderer(t)

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

	h := NewAdminIDPHandler(database, cryptoSvc, registry, renderer, auditLog, logger, t.TempDir())

	return &idpTestEnv{
		db:       database,
		crypto:   cryptoSvc,
		registry: registry,
		handler:  h,
		sm:       sm,
		audit:    auditLog,
	}
}

func (env *idpTestEnv) createAdminSession(t *testing.T) []*http.Cookie {
	t.Helper()

	hash, err := auth.HashPassword("admin-pass")
	if err != nil {
		t.Fatalf("hashing password: %v", err)
	}
	if _, err := env.db.CreateLocalAdmin(context.Background(), "admin", hash); err != nil {
		// Admin might already exist from another subtest.
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

func (env *idpTestEnv) serveWithAdminSession(t *testing.T, handler http.HandlerFunc, method, path string, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
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

func withChiURLParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func (env *idpTestEnv) createTestIDP(t *testing.T) string {
	t.Helper()

	cfg := idp.Config{
		Endpoint:       "ldap.example.com:389",
		Protocol:       "ldap",
		BaseDN:         "dc=example,dc=com",
		UserSearchBase: "ou=Users,dc=example,dc=com",
		Timeout:        10,
	}
	configJSON, _ := json.Marshal(cfg)

	secrets := idp.Secrets{
		ServiceAccountUsername: "cn=admin,dc=example,dc=com",
		ServiceAccountPassword: "secret",
	}
	secretsJSON, _ := json.Marshal(secrets)
	secretBlob, err := env.crypto.Encrypt(secretsJSON)
	if err != nil {
		t.Fatalf("encrypting secrets: %v", err)
	}

	record := &db.IdentityProviderRecord{
		ID:           "test-idp",
		FriendlyName: "Test IDP",
		Description:  "Test identity provider",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(configJSON),
		SecretBlob:   secretBlob,
	}

	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating test IDP: %v", err)
	}

	return record.ID
}

func TestIDPList(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)
	env.createTestIDP(t)

	rec := env.serveWithAdminSession(t, env.handler.List, http.MethodGet, "/admin/idp", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "idp list page") {
		t.Errorf("expected idp list content, got: %s", rec.Body.String())
	}
}

func TestIDPShowCreate(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	rec := env.serveWithAdminSession(t, env.handler.ShowCreate, http.MethodGet, "/admin/idp/new", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "idp form page") {
		t.Errorf("expected idp form content, got: %s", rec.Body.String())
	}
}

func TestIDPCreate(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("id", "new-idp")
	form.Set("friendly_name", "New IDP")
	form.Set("description", "A new identity provider")
	form.Set("provider_type", "ad")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	form.Set("base_dn", "dc=example,dc=com")
	form.Set("user_search_base", "ou=Users,dc=example,dc=com")
	form.Set("service_account_username", "cn=admin,dc=example,dc=com")
	form.Set("service_account_password", "secret123")
	form.Set("timeout", "10")
	form.Set("source_canonical_attr", "email")
	form.Set("target_directory_attr", "mail")
	form.Set("match_mode", "exact")

	rec := env.serveWithAdminSession(t, env.handler.Create, http.MethodPost, "/admin/idp", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/idp" {
		t.Errorf("expected redirect to /admin/idp, got %s", loc)
	}

	// Verify IDP was created in the database.
	record, err := env.db.GetIDP(context.Background(), "new-idp")
	if err != nil {
		t.Fatalf("getting IDP: %v", err)
	}
	if record.FriendlyName != "New IDP" {
		t.Errorf("expected friendly_name 'New IDP', got %q", record.FriendlyName)
	}

	// Verify correlation rule was created.
	rule, err := env.db.GetCorrelationRule(context.Background(), "new-idp")
	if err != nil {
		t.Fatalf("getting correlation rule: %v", err)
	}
	if rule.SourceCanonicalAttr != "email" {
		t.Errorf("expected source_canonical_attr 'email', got %q", rule.SourceCanonicalAttr)
	}
}

func TestIDPShowEdit(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDP(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.ShowEdit(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/"+idpID+"/edit", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "idp form page") {
		t.Errorf("expected idp form content, got: %s", rec.Body.String())
	}
}

func TestIDPUpdate(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDP(t)

	form := url.Values{}
	form.Set("friendly_name", "Updated IDP")
	form.Set("description", "Updated description")
	form.Set("provider_type", "ad")
	form.Set("endpoint", "ldap2.example.com:636")
	form.Set("protocol", "ldaps")
	form.Set("base_dn", "dc=example,dc=com")
	form.Set("user_search_base", "ou=People,dc=example,dc=com")
	form.Set("service_account_username", "cn=admin,dc=example,dc=com")
	form.Set("service_account_password", "newsecret")
	form.Set("timeout", "15")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.Update(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/"+idpID, cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify IDP was updated.
	record, err := env.db.GetIDP(context.Background(), idpID)
	if err != nil {
		t.Fatalf("getting IDP: %v", err)
	}
	if record.FriendlyName != "Updated IDP" {
		t.Errorf("expected friendly_name 'Updated IDP', got %q", record.FriendlyName)
	}
}

func TestIDPDelete(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDP(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.Delete(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/"+idpID+"/delete", cookies, "")

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify IDP was deleted.
	_, err := env.db.GetIDP(context.Background(), idpID)
	if err == nil {
		t.Error("expected IDP to be deleted")
	}
}

func TestIDPToggle(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDP(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.Toggle(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/"+idpID+"/toggle", cookies, "")

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify IDP was toggled (should be disabled now since it started enabled).
	record, err := env.db.GetIDP(context.Background(), idpID)
	if err != nil {
		t.Fatalf("getting IDP: %v", err)
	}
	if record.Enabled {
		t.Error("expected IDP to be disabled after toggle")
	}
}

func TestIDPTestConnection(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDP(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.TestConnection(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/"+idpID+"/test", cookies, "")

	// The test connection will fail because there's no real LDAP server,
	// but the handler should return a JSON response (not panic).
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content type, got %s", ct)
	}

	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON response: %v", err)
	}

	// Connection should fail since there's no real LDAP server.
	if result["status"] != "error" {
		t.Logf("test connection result: %v", result)
	}
}

func TestIDPCreateMissingID(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("friendly_name", "No ID IDP")
	// Omit "id" field

	rec := env.serveWithAdminSession(t, env.handler.Create, http.MethodPost, "/admin/idp", cookies, form.Encode())

	// Should re-render the form (200), not redirect.
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 (form re-render), got %d", rec.Code)
	}
}

// TestLoadProviders verifies that LoadProviders runs without error on an empty DB.
func TestLoadProviders(t *testing.T) {
	env := setupIDPTest(t)
	if err := env.handler.LoadProviders(context.Background()); err != nil {
		t.Errorf("LoadProviders failed: %v", err)
	}
}

// TestLoadProviders_WithIDP verifies that LoadProviders attempts to register providers.
func TestLoadProviders_WithIDP(t *testing.T) {
	env := setupIDPTest(t)
	env.createTestIDP(t)

	// LoadProviders will try to build the provider from DB config.
	// The config stored by createTestIDP has an LDAP endpoint that won't be
	// connectable in tests, so we just check it runs without panicking.
	_ = env.handler.LoadProviders(context.Background())
}

// TestTestConnectionFromForm_MissingFields verifies that TestConnectionFromForm
// returns 400 when endpoint or protocol are missing.
func TestTestConnectionFromForm_MissingFields(t *testing.T) {
	env := setupIDPTest(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/idp/test-connection", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	env.handler.TestConnectionFromForm(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestIDPShowEdit_NotFound covers the GetIDP error branch in ShowEdit.
func TestIDPShowEdit_NotFound(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "nonexistent-idp")
		env.handler.ShowEdit(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/nonexistent-idp/edit", cookies, "")

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

// TestIDPShowEdit_WithMFAProvider covers the MFAProviderID != nil and defaultMFAIDPtr != nil branches.
func TestIDPShowEdit_WithMFAProvider(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	// Create an MFA provider.
	mfaID := "mfa-test"
	if err := env.db.CreateMFAProvider(context.Background(), &db.MFAProviderRecord{
		ID:           mfaID,
		Name:         "Test MFA",
		ProviderType: "email",
		Enabled:      true,
		ConfigJSON:   `{"from":"mfa@example.com"}`,
	}); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}

	// Set it as default.
	if err := env.db.SetDefaultMFAProviderID(context.Background(), &mfaID); err != nil {
		t.Fatalf("setting default MFA provider: %v", err)
	}

	// Create an IDP with the MFA provider linked.
	idpID := env.createTestIDP(t)
	// Update the record to have mfa_provider_id set.
	record, err := env.db.GetIDP(context.Background(), idpID)
	if err != nil {
		t.Fatalf("getting IDP: %v", err)
	}
	record.MFAProviderID = &mfaID
	if err := env.db.UpdateIDP(context.Background(), record); err != nil {
		t.Fatalf("updating IDP: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.ShowEdit(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/"+idpID+"/edit", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestIDPToggle_NotFound covers the GetIDP error branch in Toggle.
func TestIDPToggle_NotFound(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "nonexistent-idp")
		env.handler.Toggle(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/nonexistent-idp/toggle", cookies, "")

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

// TestIDPToggle_Enable creates a disabled IDP and toggles it to enabled,
// covering the newEnabled == true branch in Toggle.
func TestIDPToggle_Enable(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDP(t)

	// Disable the IDP first.
	if err := env.db.ToggleIDP(context.Background(), idpID, false); err != nil {
		t.Fatalf("disabling IDP: %v", err)
	}

	// Now toggle it (should re-enable).
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.Toggle(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/"+idpID+"/toggle", cookies, "")

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d; body: %s", rec.Code, rec.Body.String())
	}

	record, err := env.db.GetIDP(context.Background(), idpID)
	if err != nil {
		t.Fatalf("getting IDP: %v", err)
	}
	if !record.Enabled {
		t.Error("expected IDP to be enabled after toggle")
	}
}

// TestIDPCreate_WithAttributeMappings covers the len(mappings) > 0 branch in Create.
func TestIDPCreate_WithAttributeMappings(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("id", "idp-attrs")
	form.Set("friendly_name", "IDP With Attrs")
	form.Set("provider_type", "ad")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	form.Set("base_dn", "dc=example,dc=com")
	form.Set("user_search_base", "ou=Users,dc=example,dc=com")
	form.Set("timeout", "10")
	// Attribute mappings
	form["canonical_name[]"] = []string{"email", "username"}
	form["directory_attr[]"] = []string{"mail", "sAMAccountName"}

	rec := env.serveWithAdminSession(t, env.handler.Create, http.MethodPost, "/admin/idp", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d; body: %s", rec.Code, rec.Body.String())
	}

	mappings, err := env.db.ListAttributeMappings(context.Background(), "idp-attrs")
	if err != nil {
		t.Fatalf("listing attribute mappings: %v", err)
	}
	if len(mappings) != 2 {
		t.Errorf("expected 2 attribute mappings, got %d", len(mappings))
	}
}

// TestIDPCreate_WithMFAProviderID covers the mfa_provider_id != "" branch in Create.
func TestIDPCreate_WithMFAProviderID(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	// Create an MFA provider to reference.
	mfaID := "mfa-for-create"
	if err := env.db.CreateMFAProvider(context.Background(), &db.MFAProviderRecord{
		ID:           mfaID,
		Name:         "Test MFA",
		ProviderType: "email",
		Enabled:      true,
		ConfigJSON:   `{"from":"mfa@example.com"}`,
	}); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}

	form := url.Values{}
	form.Set("id", "idp-with-mfa")
	form.Set("friendly_name", "IDP With MFA")
	form.Set("provider_type", "ad")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	form.Set("base_dn", "dc=example,dc=com")
	form.Set("user_search_base", "ou=Users,dc=example,dc=com")
	form.Set("timeout", "10")
	form.Set("mfa_provider_id", mfaID)

	rec := env.serveWithAdminSession(t, env.handler.Create, http.MethodPost, "/admin/idp", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d; body: %s", rec.Code, rec.Body.String())
	}

	record, err := env.db.GetIDP(context.Background(), "idp-with-mfa")
	if err != nil {
		t.Fatalf("getting IDP: %v", err)
	}
	if record.MFAProviderID == nil || *record.MFAProviderID != mfaID {
		t.Errorf("expected MFAProviderID %q, got %v", mfaID, record.MFAProviderID)
	}
}

// TestIDPUpdate_NotFound covers the GetIDP error branch in Update.
func TestIDPUpdate_NotFound(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("friendly_name", "Updated")
	form.Set("provider_type", "ad")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	form.Set("timeout", "10")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "nonexistent-idp")
		env.handler.Update(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/nonexistent-idp", cookies, form.Encode())

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

// TestIDPUpdate_PreserveSecrets covers the blank credentials branch in Update.
func TestIDPUpdate_PreserveSecrets(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDP(t)

	form := url.Values{}
	form.Set("friendly_name", "Updated IDP")
	form.Set("description", "desc")
	form.Set("provider_type", "ad")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	form.Set("base_dn", "dc=example,dc=com")
	form.Set("user_search_base", "ou=Users,dc=example,dc=com")
	form.Set("timeout", "10")
	// No service_account_username or service_account_password — should preserve existing.

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.Update(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/"+idpID, cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify secrets were preserved.
	record, err := env.db.GetIDP(context.Background(), idpID)
	if err != nil {
		t.Fatalf("getting IDP: %v", err)
	}
	if len(record.SecretBlob) == 0 {
		t.Error("expected non-empty secret blob (secrets should be preserved)")
	}
	plaintext, err := env.crypto.Decrypt(record.SecretBlob)
	if err != nil {
		t.Fatalf("decrypting secrets: %v", err)
	}
	var secrets idp.Secrets
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		t.Fatalf("unmarshaling secrets: %v", err)
	}
	if secrets.ServiceAccountPassword == "" {
		t.Error("expected preserved service account password, got empty")
	}
}

// TestIDPUpdate_DeleteCorrelationRule covers the rule == nil branch in Update,
// which deletes the existing correlation rule when source_canonical_attr is empty.
func TestIDPUpdate_DeleteCorrelationRule(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDP(t)

	// First create a correlation rule.
	if err := env.db.SetCorrelationRule(context.Background(), &db.CorrelationRule{
		IDPID:               idpID,
		SourceCanonicalAttr: "email",
		MatchMode:           "exact",
	}); err != nil {
		t.Fatalf("creating correlation rule: %v", err)
	}

	// Update without source_canonical_attr → rule should be deleted.
	form := url.Values{}
	form.Set("friendly_name", "Updated")
	form.Set("provider_type", "ad")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	form.Set("base_dn", "dc=example,dc=com")
	form.Set("user_search_base", "ou=Users,dc=example,dc=com")
	form.Set("timeout", "10")
	// No source_canonical_attr

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.Update(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/"+idpID, cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleLogoUpload_RemoveLogo covers the remove_logo == "1" branch.
func TestHandleLogoUpload_RemoveLogo(t *testing.T) {
	env := setupIDPTest(t)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("remove_logo", "1") //nolint:errcheck
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if err := req.ParseMultipartForm(5 << 20); err != nil {
		t.Fatalf("parsing multipart form: %v", err)
	}

	result := env.handler.handleLogoUpload(req, "test-idp", "/uploads/old-logo.png")
	if result != "" {
		t.Errorf("expected empty string after remove_logo, got %q", result)
	}
}

// TestHandleLogoUpload_ValidPNG covers the successful PNG file upload path.
func TestHandleLogoUpload_ValidPNG(t *testing.T) {
	env := setupIDPTest(t)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("logo_file", "logo.png")
	if err != nil {
		t.Fatalf("creating form file: %v", err)
	}
	io.WriteString(fw, "fake png data") //nolint:errcheck
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if err := req.ParseMultipartForm(5 << 20); err != nil {
		t.Fatalf("parsing multipart form: %v", err)
	}

	result := env.handler.handleLogoUpload(req, "test-idp", "")
	if result != "/uploads/idp-logo-test-idp.png" {
		t.Errorf("unexpected logo URL: %q", result)
	}
}

// TestHandleLogoUpload_InvalidExtension covers the extension check branch.
func TestHandleLogoUpload_InvalidExtension(t *testing.T) {
	env := setupIDPTest(t)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("logo_file", "script.exe")
	if err != nil {
		t.Fatalf("creating form file: %v", err)
	}
	io.WriteString(fw, "not an image") //nolint:errcheck
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if err := req.ParseMultipartForm(5 << 20); err != nil {
		t.Fatalf("parsing multipart form: %v", err)
	}

	currentURL := "/uploads/current-logo.png"
	result := env.handler.handleLogoUpload(req, "test-idp", currentURL)
	if result != currentURL {
		t.Errorf("expected current URL %q for invalid extension, got %q", currentURL, result)
	}
}

// ============================================================
// mockIDPErrStore — wraps *db.DB and overrides specific IDP
// methods to inject errors for error-path coverage.
// ============================================================

type mockIDPErrStore struct {
	*db.DB
	listIDPsErr              error
	listEnabledIDPsErr       error
	listEnabledIDPsRecords   []db.IdentityProviderRecord
	getIDPErr                error
	getIDPRecord             *db.IdentityProviderRecord
	createIDPErr             error
	updateIDPErr             error
	bypassUpdateIDP          bool
	deleteIDPErr             error
	toggleIDPErr             error
	listAttributeMappingsErr error
	setAttributeMappingsErr  error
	setCorrelationRuleErr    error
}

func (m *mockIDPErrStore) ListIDPs(ctx context.Context) ([]db.IdentityProviderRecord, error) {
	if m.listIDPsErr != nil {
		return nil, m.listIDPsErr
	}
	return m.DB.ListIDPs(ctx)
}

func (m *mockIDPErrStore) ListEnabledIDPs(ctx context.Context) ([]db.IdentityProviderRecord, error) {
	if m.listEnabledIDPsErr != nil {
		return nil, m.listEnabledIDPsErr
	}
	if m.listEnabledIDPsRecords != nil {
		return m.listEnabledIDPsRecords, nil
	}
	return m.DB.ListEnabledIDPs(ctx)
}

func (m *mockIDPErrStore) GetIDP(ctx context.Context, id string) (*db.IdentityProviderRecord, error) {
	if m.getIDPErr != nil {
		return nil, m.getIDPErr
	}
	if m.getIDPRecord != nil {
		return m.getIDPRecord, nil
	}
	return m.DB.GetIDP(ctx, id)
}

func (m *mockIDPErrStore) CreateIDP(ctx context.Context, record *db.IdentityProviderRecord) error {
	if m.createIDPErr != nil {
		return m.createIDPErr
	}
	return m.DB.CreateIDP(ctx, record)
}

func (m *mockIDPErrStore) UpdateIDP(ctx context.Context, record *db.IdentityProviderRecord) error {
	if m.updateIDPErr != nil {
		return m.updateIDPErr
	}
	if m.bypassUpdateIDP {
		return nil
	}
	return m.DB.UpdateIDP(ctx, record)
}

func (m *mockIDPErrStore) DeleteIDP(ctx context.Context, id string) error {
	if m.deleteIDPErr != nil {
		return m.deleteIDPErr
	}
	return m.DB.DeleteIDP(ctx, id)
}

func (m *mockIDPErrStore) ToggleIDP(ctx context.Context, id string, enabled bool) error {
	if m.toggleIDPErr != nil {
		return m.toggleIDPErr
	}
	return m.DB.ToggleIDP(ctx, id, enabled)
}

func (m *mockIDPErrStore) ListAttributeMappings(ctx context.Context, idpID string) ([]db.AttributeMapping, error) {
	if m.listAttributeMappingsErr != nil {
		return nil, m.listAttributeMappingsErr
	}
	return m.DB.ListAttributeMappings(ctx, idpID)
}

func (m *mockIDPErrStore) SetAttributeMappings(ctx context.Context, idpID string, mappings []db.AttributeMapping) error {
	if m.setAttributeMappingsErr != nil {
		return m.setAttributeMappingsErr
	}
	return m.DB.SetAttributeMappings(ctx, idpID, mappings)
}

func (m *mockIDPErrStore) SetCorrelationRule(ctx context.Context, rule *db.CorrelationRule) error {
	if m.setCorrelationRuleErr != nil {
		return m.setCorrelationRuleErr
	}
	return m.DB.SetCorrelationRule(ctx, rule)
}

// newIDPMockEnv creates an idpTestEnv whose handler uses the mock store.
// The caller-provided database is used directly for session management.
func newIDPMockEnv(t *testing.T, database *db.DB, mock *mockIDPErrStore) *idpTestEnv {
	t.Helper()
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
	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := stubIDPRenderer(t)
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
	h := NewAdminIDPHandler(mock, cryptoSvc, registry, renderer, auditLog, logger, t.TempDir())
	return &idpTestEnv{
		db:       database,
		crypto:   cryptoSvc,
		registry: registry,
		handler:  h,
		sm:       sm,
		audit:    auditLog,
	}
}

// ============================================================
// List error path
// ============================================================

// TestIDPList_DBError covers List when ListIDPs fails → 500.
func TestIDPList_DBError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockIDPErrStore{DB: database, listIDPsErr: fmt.Errorf("DB read failed")}
	env := newIDPMockEnv(t, database, mock)

	req := httptest.NewRequest(http.MethodGet, "/admin/idp", nil)
	rec := httptest.NewRecorder()
	env.handler.List(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when ListIDPs fails, got %d", rec.Code)
	}
}

// ============================================================
// Create error paths
// ============================================================

// TestIDPCreate_DBError covers Create when CreateIDP fails → re-renders form (200).
func TestIDPCreate_DBError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockIDPErrStore{DB: database, createIDPErr: fmt.Errorf("DB write failed")}
	env := newIDPMockEnv(t, database, mock)
	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("id", "new-idp-fail")
	form.Set("friendly_name", "New IDP")
	form.Set("provider_type", "ad")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	form.Set("base_dn", "dc=example,dc=com")
	form.Set("user_search_base", "ou=Users,dc=example,dc=com")
	form.Set("timeout", "10")

	rec := env.serveWithAdminSession(t, env.handler.Create, http.MethodPost, "/admin/idp", cookies, form.Encode())

	// CreateIDP failure re-renders form with error (200).
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (form re-render) when CreateIDP fails, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "idp form page") {
		t.Errorf("expected idp form page re-render, got: %s", rec.Body.String())
	}
}

// ============================================================
// ShowEdit error paths
// ============================================================

// TestIDPShowEdit_InvalidConfigJSON covers the json.Unmarshal config error in ShowEdit → 500.
func TestIDPShowEdit_InvalidConfigJSON(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	record := &db.IdentityProviderRecord{
		ID:           "bad-cfg-edit",
		FriendlyName: "Bad Config Edit",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   "not-valid-json{",
	}
	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", record.ID)
		env.handler.ShowEdit(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/"+record.ID+"/edit", cookies, "")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for invalid config JSON in ShowEdit, got %d", rec.Code)
	}
}

// TestIDPShowEdit_DecryptError covers the crypto.Decrypt error in ShowEdit → 500.
func TestIDPShowEdit_DecryptError(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	cfg := idp.Config{Endpoint: "ldap.example.com:389", Protocol: "ldap", Timeout: 10}
	configJSON, _ := json.Marshal(cfg)

	record := &db.IdentityProviderRecord{
		ID:           "bad-secret-edit",
		FriendlyName: "Bad Secret Edit",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(configJSON),
		SecretBlob:   []byte("not-valid-ciphertext"),
	}
	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", record.ID)
		env.handler.ShowEdit(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/"+record.ID+"/edit", cookies, "")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for decrypt error in ShowEdit, got %d", rec.Code)
	}
}

// TestIDPShowEdit_InvalidSecretsJSON covers the json.Unmarshal secrets error in ShowEdit → 500.
func TestIDPShowEdit_InvalidSecretsJSON(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	cfg := idp.Config{Endpoint: "ldap.example.com:389", Protocol: "ldap", Timeout: 10}
	configJSON, _ := json.Marshal(cfg)

	// Encrypt content that decrypts to invalid JSON.
	secretBlob, err := env.crypto.Encrypt([]byte("not-valid-json{"))
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	record := &db.IdentityProviderRecord{
		ID:           "bad-secrets-json-edit",
		FriendlyName: "Bad Secrets JSON Edit",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(configJSON),
		SecretBlob:   secretBlob,
	}
	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", record.ID)
		env.handler.ShowEdit(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/"+record.ID+"/edit", cookies, "")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for invalid secrets JSON in ShowEdit, got %d", rec.Code)
	}
}

// ============================================================
// Update error paths
// ============================================================

// TestIDPUpdate_DBError covers Update when UpdateIDP fails → 500.
func TestIDPUpdate_DBError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockIDPErrStore{DB: database, updateIDPErr: fmt.Errorf("DB write failed")}
	env := newIDPMockEnv(t, database, mock)
	cookies := env.createAdminSession(t)

	// Create a real IDP so GetIDP succeeds.
	cfg := idp.Config{Endpoint: "ldap.example.com:389", Protocol: "ldap", Timeout: 10}
	configJSON, _ := json.Marshal(cfg)
	record := &db.IdentityProviderRecord{
		ID:           "update-err-idp",
		FriendlyName: "Update Err IDP",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(configJSON),
	}
	if err := database.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	form := url.Values{}
	form.Set("friendly_name", "Updated")
	form.Set("provider_type", "ad")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	form.Set("base_dn", "dc=example,dc=com")
	form.Set("timeout", "10")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", record.ID)
		env.handler.Update(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/"+record.ID, cookies, form.Encode())
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when UpdateIDP fails, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestIDPUpdate_RegisterProviderFails covers Update where registerProvider fails (logged, not HTTP error).
// This exercises the "provider updated but failed to re-register" log path.
func TestIDPUpdate_RegisterProviderFails(t *testing.T) {
	database := setupTestDB(t)
	// bypassUpdateIDP=true: UpdateIDP returns nil without calling the real DB,
	// so provider_type "unknown_type" won't hit the CHECK constraint.
	mock := &mockIDPErrStore{DB: database, bypassUpdateIDP: true}
	env := newIDPMockEnv(t, database, mock)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDP(t)

	// Update with unknown provider type: UpdateIDP (mock) succeeds, registerProvider fails (logged).
	form := url.Values{}
	form.Set("friendly_name", "Updated IDP")
	form.Set("provider_type", "unknown_type")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	form.Set("base_dn", "dc=example,dc=com")
	form.Set("user_search_base", "ou=Users,dc=example,dc=com")
	form.Set("timeout", "10")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.Update(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/"+idpID, cookies, form.Encode())
	// registerProvider error is only logged → still redirects.
	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 even when registerProvider fails, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ============================================================
// Delete error path
// ============================================================

// TestIDPDelete_DBError covers Delete when DeleteIDP fails → 500.
func TestIDPDelete_DBError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockIDPErrStore{DB: database, deleteIDPErr: fmt.Errorf("DB write failed")}
	env := newIDPMockEnv(t, database, mock)

	// DeleteIDP error is returned before audit log uses sess, so no session required.
	req := withChiURLParam(
		httptest.NewRequest(http.MethodPost, "/admin/idp/some-idp/delete", nil),
		"id", "some-idp",
	)
	rec := httptest.NewRecorder()
	env.handler.Delete(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when DeleteIDP fails, got %d", rec.Code)
	}
}

// ============================================================
// Toggle error path
// ============================================================

// TestIDPToggle_ToggleDBError covers Toggle when ToggleIDP fails → 500.
func TestIDPToggle_ToggleDBError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockIDPErrStore{DB: database, toggleIDPErr: fmt.Errorf("DB write failed")}
	env := newIDPMockEnv(t, database, mock)

	// Create a real IDP so GetIDP succeeds.
	cfg := idp.Config{Endpoint: "ldap.example.com:389", Protocol: "ldap", Timeout: 10}
	configJSON, _ := json.Marshal(cfg)
	record := &db.IdentityProviderRecord{
		ID:           "toggle-err-idp",
		FriendlyName: "Toggle Err IDP",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(configJSON),
	}
	if err := database.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	// ToggleIDP error is returned before audit log uses sess, so no session required.
	req := withChiURLParam(
		httptest.NewRequest(http.MethodPost, "/admin/idp/"+record.ID+"/toggle", nil),
		"id", record.ID,
	)
	rec := httptest.NewRecorder()
	env.handler.Toggle(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when ToggleIDP fails, got %d", rec.Code)
	}
}

// ============================================================
// TestConnection error paths
// ============================================================

// TestIDPTestConnection_InvalidConfigJSON covers TestConnection when config JSON is invalid → 500 JSON.
func TestIDPTestConnection_InvalidConfigJSON(t *testing.T) {
	env := setupIDPTest(t)

	record := &db.IdentityProviderRecord{
		ID:           "bad-cfg-tc",
		FriendlyName: "Bad Config TC",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   "not-valid-json{",
	}
	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	// Error return is before audit log, so no session needed.
	req := withChiURLParam(
		httptest.NewRequest(http.MethodPost, "/admin/idp/"+record.ID+"/test", nil),
		"id", record.ID,
	)
	rec := httptest.NewRecorder()
	env.handler.TestConnection(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for invalid config JSON in TestConnection, got %d", rec.Code)
	}
	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON response: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected error status, got %s", result["status"])
	}
}

// TestIDPTestConnection_DecryptError covers TestConnection when decrypt fails → 500 JSON.
func TestIDPTestConnection_DecryptError(t *testing.T) {
	env := setupIDPTest(t)

	cfg := idp.Config{Endpoint: "ldap.example.com:389", Protocol: "ldap", Timeout: 10}
	configJSON, _ := json.Marshal(cfg)

	record := &db.IdentityProviderRecord{
		ID:           "bad-secret-tc",
		FriendlyName: "Bad Secret TC",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(configJSON),
		SecretBlob:   []byte("not-valid-ciphertext"),
	}
	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	req := withChiURLParam(
		httptest.NewRequest(http.MethodPost, "/admin/idp/"+record.ID+"/test", nil),
		"id", record.ID,
	)
	rec := httptest.NewRecorder()
	env.handler.TestConnection(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for decrypt error in TestConnection, got %d", rec.Code)
	}
	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON response: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected error status, got %s", result["status"])
	}
}

// TestIDPTestConnection_InvalidSecretsJSON covers TestConnection when secrets JSON is invalid → 500 JSON.
func TestIDPTestConnection_InvalidSecretsJSON(t *testing.T) {
	env := setupIDPTest(t)

	cfg := idp.Config{Endpoint: "ldap.example.com:389", Protocol: "ldap", Timeout: 10}
	configJSON, _ := json.Marshal(cfg)

	// Encrypt content that decrypts to invalid JSON.
	secretBlob, err := env.crypto.Encrypt([]byte("not-valid-json{"))
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	record := &db.IdentityProviderRecord{
		ID:           "bad-secrets-json-tc",
		FriendlyName: "Bad Secrets JSON TC",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(configJSON),
		SecretBlob:   secretBlob,
	}
	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	req := withChiURLParam(
		httptest.NewRequest(http.MethodPost, "/admin/idp/"+record.ID+"/test", nil),
		"id", record.ID,
	)
	rec := httptest.NewRecorder()
	env.handler.TestConnection(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for invalid secrets JSON in TestConnection, got %d", rec.Code)
	}
	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON response: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected error status, got %s", result["status"])
	}
}

// TestIDPTestConnection_UnknownProviderType covers TestConnection when buildProvider fails → 500 JSON.
func TestIDPTestConnection_UnknownProviderType(t *testing.T) {
	database := setupTestDB(t)
	cfg := idp.Config{Endpoint: "ldap.example.com:389", Protocol: "ldap", Timeout: 10}
	configJSON, _ := json.Marshal(cfg)
	// Return an IDP with unknown provider_type via mock (bypasses DB CHECK constraint).
	fakeRecord := &db.IdentityProviderRecord{
		ID:           "unknown-type-tc",
		FriendlyName: "Unknown Type TC",
		ProviderType: "unknown_type",
		Enabled:      true,
		ConfigJSON:   string(configJSON),
	}
	mock := &mockIDPErrStore{DB: database, getIDPRecord: fakeRecord}
	env := newIDPMockEnv(t, database, mock)

	req := withChiURLParam(
		httptest.NewRequest(http.MethodPost, "/admin/idp/unknown-type-tc/test", nil),
		"id", fakeRecord.ID,
	)
	rec := httptest.NewRecorder()
	env.handler.TestConnection(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for unknown provider type in TestConnection, got %d", rec.Code)
	}
	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON response: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected error status, got %s", result["status"])
	}
}

// ============================================================
// TestConnectionFromForm additional edge cases
// ============================================================

// TestIDPTestConnectionFromForm_UnknownProviderType covers buildProvider failure → 500 JSON.
func TestIDPTestConnectionFromForm_UnknownProviderType(t *testing.T) {
	env := setupIDPTest(t)

	form := url.Values{}
	form.Set("provider_type", "unknown_provider_xyz")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	form.Set("service_account_username", "cn=admin,dc=example,dc=com")
	form.Set("service_account_password", "secret")

	req := httptest.NewRequest(http.MethodPost, "/admin/idp/test-connection", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.TestConnectionFromForm(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for unknown provider type in TestConnectionFromForm, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON response: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected error status, got %s", result["status"])
	}
}

// TestIDPTestConnectionFromForm_EmptyProviderType covers the default-to-"ad" branch
// when provider_type is empty but credentials are provided.
func TestIDPTestConnectionFromForm_EmptyProviderType(t *testing.T) {
	env := setupIDPTest(t)

	form := url.Values{}
	// No provider_type — should default to "ad".
	form.Set("endpoint", "127.0.0.1:1") // unreachable, connection will fail
	form.Set("protocol", "ldap")
	form.Set("service_account_username", "cn=admin,dc=example,dc=com")
	form.Set("service_account_password", "secret")

	req := httptest.NewRequest(http.MethodPost, "/admin/idp/test-connection", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.TestConnectionFromForm(rec, req)

	// Should return a JSON response (connection fails, but handler doesn't panic).
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON response for empty provider_type, got content-type: %s", ct)
	}
}

// TestIDPTestConnectionFromForm_SavedPasswordEmpty covers the specific error message
// when idpID is provided but the saved password is empty after credential fallback.
func TestIDPTestConnectionFromForm_SavedPasswordEmpty(t *testing.T) {
	env := setupIDPTest(t)

	// Create IDP with a username but empty password in saved secrets.
	cfg := idp.Config{Endpoint: "ldap.example.com:389", Protocol: "ldap", Timeout: 10}
	configJSON, _ := json.Marshal(cfg)
	secrets := idp.Secrets{ServiceAccountUsername: "cn=admin,dc=example,dc=com", ServiceAccountPassword: ""}
	secretsJSON, _ := json.Marshal(secrets)
	secretBlob, _ := env.crypto.Encrypt(secretsJSON)

	record := &db.IdentityProviderRecord{
		ID:           "empty-pass-idp",
		FriendlyName: "Empty Pass IDP",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(configJSON),
		SecretBlob:   secretBlob,
	}
	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	form := url.Values{}
	form.Set("id", record.ID)
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	// No credentials in form — will load from DB, but saved password is empty.

	req := httptest.NewRequest(http.MethodPost, "/admin/idp/test-connection", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.TestConnectionFromForm(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty saved password, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON response: %v", err)
	}
	if !strings.Contains(result["message"], "Saved password is empty") {
		t.Errorf("expected 'Saved password is empty' message, got: %s", result["message"])
	}
}

// TestIDPTestConnectionFromForm_DecryptSavedSecretsFails covers the log path when
// decrypt fails during credential fallback (falls through to 400 for missing creds).
func TestIDPTestConnectionFromForm_DecryptSavedSecretsFails(t *testing.T) {
	env := setupIDPTest(t)

	cfg := idp.Config{Endpoint: "ldap.example.com:389", Protocol: "ldap", Timeout: 10}
	configJSON, _ := json.Marshal(cfg)

	record := &db.IdentityProviderRecord{
		ID:           "bad-secret-form",
		FriendlyName: "Bad Secret Form",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(configJSON),
		SecretBlob:   []byte("not-valid-ciphertext"),
	}
	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	form := url.Values{}
	form.Set("id", record.ID)
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	// No credentials — decrypt fails → logs debug, creds still empty → 400.

	req := httptest.NewRequest(http.MethodPost, "/admin/idp/test-connection", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.TestConnectionFromForm(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when decrypt fails in fallback, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestIDPTestConnectionFromForm_ParseSavedSecretsFails covers the log path when
// unmarshal of decrypted secrets fails during credential fallback.
func TestIDPTestConnectionFromForm_ParseSavedSecretsFails(t *testing.T) {
	env := setupIDPTest(t)

	cfg := idp.Config{Endpoint: "ldap.example.com:389", Protocol: "ldap", Timeout: 10}
	configJSON, _ := json.Marshal(cfg)

	// Encrypt content that decrypts to invalid JSON.
	secretBlob, err := env.crypto.Encrypt([]byte("not-valid-json{"))
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	record := &db.IdentityProviderRecord{
		ID:           "bad-secrets-json-form",
		FriendlyName: "Bad Secrets JSON Form",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(configJSON),
		SecretBlob:   secretBlob,
	}
	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	form := url.Values{}
	form.Set("id", record.ID)
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	// No credentials — parse fails → logs debug, creds still empty → 400.

	req := httptest.NewRequest(http.MethodPost, "/admin/idp/test-connection", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.TestConnectionFromForm(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when parse fails in fallback, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ============================================================
// getLDAPConn error paths (tested via BrowseChildren)
// ============================================================

// TestGetLDAPConn_InvalidConfigJSON covers the json.Unmarshal config error in getLDAPConn.
func TestGetLDAPConn_InvalidConfigJSON(t *testing.T) {
	env := setupIDPTest(t)

	record := &db.IdentityProviderRecord{
		ID:           "bad-cfg-ldap",
		FriendlyName: "Bad Config LDAP",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   "not-valid-json{",
	}
	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	// Set a mock connector — it won't be reached since config parse fails first.
	env.handler.connector = &handlerMockLDAPConnector{conn: &handlerMockLDAPConn{}}

	req := withChiURLParam(
		httptest.NewRequest(http.MethodGet, "/admin/idp/"+record.ID+"/browse", nil),
		"id", record.ID,
	)
	rec := httptest.NewRecorder()
	env.handler.BrowseChildren(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for invalid config JSON in getLDAPConn, got %d", rec.Code)
	}
}

// TestGetLDAPConn_DecryptError covers the crypto.Decrypt error in getLDAPConn.
func TestGetLDAPConn_DecryptError(t *testing.T) {
	env := setupIDPTest(t)

	cfg := idp.Config{Endpoint: "ldap.example.com:389", Protocol: "ldap", Timeout: 10}
	configJSON, _ := json.Marshal(cfg)

	record := &db.IdentityProviderRecord{
		ID:           "bad-secret-ldap",
		FriendlyName: "Bad Secret LDAP",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(configJSON),
		SecretBlob:   []byte("not-valid-ciphertext"),
	}
	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	env.handler.connector = &handlerMockLDAPConnector{conn: &handlerMockLDAPConn{}}

	req := withChiURLParam(
		httptest.NewRequest(http.MethodGet, "/admin/idp/"+record.ID+"/browse", nil),
		"id", record.ID,
	)
	rec := httptest.NewRecorder()
	env.handler.BrowseChildren(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for decrypt error in getLDAPConn, got %d", rec.Code)
	}
}

// TestGetLDAPConn_InvalidSecretsJSON covers the json.Unmarshal secrets error in getLDAPConn.
func TestGetLDAPConn_InvalidSecretsJSON(t *testing.T) {
	env := setupIDPTest(t)

	cfg := idp.Config{Endpoint: "ldap.example.com:389", Protocol: "ldap", Timeout: 10}
	configJSON, _ := json.Marshal(cfg)

	secretBlob, err := env.crypto.Encrypt([]byte("not-valid-json{"))
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	record := &db.IdentityProviderRecord{
		ID:           "bad-secrets-json-ldap",
		FriendlyName: "Bad Secrets JSON LDAP",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(configJSON),
		SecretBlob:   secretBlob,
	}
	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	env.handler.connector = &handlerMockLDAPConnector{conn: &handlerMockLDAPConn{}}

	req := withChiURLParam(
		httptest.NewRequest(http.MethodGet, "/admin/idp/"+record.ID+"/browse", nil),
		"id", record.ID,
	)
	rec := httptest.NewRecorder()
	env.handler.BrowseChildren(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for invalid secrets JSON in getLDAPConn, got %d", rec.Code)
	}
}

// ============================================================
// BrowsePage error path
// ============================================================

// TestBrowsePage_InvalidConfigJSON covers BrowsePage when config JSON is invalid → 500.
// Uses setupBrowseTest which has admin_idp_browse.html registered.
func TestBrowsePage_InvalidConfigJSON(t *testing.T) {
	env := setupBrowseTest(t)
	cookies := env.createAdminSession(t)

	record := &db.IdentityProviderRecord{
		ID:           "bad-cfg-browse",
		FriendlyName: "Bad Config Browse",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   "not-valid-json{",
	}
	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", record.ID)
		env.handler.BrowsePage(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/"+record.ID+"/browse-page", cookies, "")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for invalid config JSON in BrowsePage, got %d", rec.Code)
	}
}

// ============================================================
// buildProvider unit test
// ============================================================

// TestBuildProvider_UnknownType covers the default/unknown branch in buildProvider → error.
func TestBuildProvider_UnknownType(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := idp.Config{}
	secrets := idp.Secrets{}

	_, err := buildProvider("test-id", "unknown_type_xyz", cfg, secrets, logger)
	if err == nil {
		t.Error("expected error for unknown provider type in buildProvider")
	}
	if !strings.Contains(err.Error(), "unsupported provider type") {
		t.Errorf("expected 'unsupported provider type' in error, got: %v", err)
	}
}

// ============================================================
// LoadProviders error paths
// ============================================================

// TestLoadProviders_DBError covers LoadProviders when ListEnabledIDPs fails → error returned.
func TestLoadProviders_DBError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockIDPErrStore{DB: database, listEnabledIDPsErr: fmt.Errorf("DB read failed")}
	env := newIDPMockEnv(t, database, mock)

	err := env.handler.LoadProviders(context.Background())
	if err == nil {
		t.Error("expected error when ListEnabledIDPs fails")
	}
	if !strings.Contains(err.Error(), "listing enabled IDPs") {
		t.Errorf("expected 'listing enabled IDPs' in error, got: %v", err)
	}
}

// TestLoadProviders_WithBadProviderType covers LoadProviders when registerProvider fails
// due to an unknown provider type (error is logged, LoadProviders returns nil).
func TestLoadProviders_WithBadProviderType(t *testing.T) {
	database := setupTestDB(t)
	cfg := idp.Config{Endpoint: "ldap.example.com:389", Protocol: "ldap", Timeout: 10}
	configJSON, _ := json.Marshal(cfg)
	// Inject a record with unknown_type via mock (bypasses DB CHECK constraint).
	fakeRecords := []db.IdentityProviderRecord{
		{
			ID:           "bad-type-load",
			FriendlyName: "Bad Type Load",
			ProviderType: "unknown_type",
			Enabled:      true,
			ConfigJSON:   string(configJSON),
		},
	}
	mock := &mockIDPErrStore{DB: database, listEnabledIDPsRecords: fakeRecords}
	env := newIDPMockEnv(t, database, mock)

	// LoadProviders logs the error but continues, returning nil.
	err := env.handler.LoadProviders(context.Background())
	if err != nil {
		t.Errorf("LoadProviders should return nil even with bad provider type: %v", err)
	}
}

// TestLoadProviders_WithInvalidConfigJSON covers LoadProviders when registerProvider
// fails due to invalid config JSON (error is logged, LoadProviders returns nil).
func TestLoadProviders_WithInvalidConfigJSON(t *testing.T) {
	env := setupIDPTest(t)

	record := &db.IdentityProviderRecord{
		ID:           "bad-cfg-load",
		FriendlyName: "Bad Config Load",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   "not-valid-json{",
	}
	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	// LoadProviders logs the error but continues, returning nil.
	err := env.handler.LoadProviders(context.Background())
	if err != nil {
		t.Errorf("LoadProviders should return nil even with bad config JSON: %v", err)
	}
}

// TestLoadProviders_WithDecryptError covers LoadProviders when registerProvider
// fails due to SecretBlob decrypt error (error is logged, LoadProviders returns nil).
func TestLoadProviders_WithDecryptError(t *testing.T) {
	env := setupIDPTest(t)

	cfg := idp.Config{Endpoint: "ldap.example.com:389", Protocol: "ldap", Timeout: 10}
	configJSON, _ := json.Marshal(cfg)

	record := &db.IdentityProviderRecord{
		ID:           "bad-secret-load",
		FriendlyName: "Bad Secret Load",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(configJSON),
		SecretBlob:   []byte("not-valid-ciphertext"),
	}
	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	// LoadProviders logs the error but continues, returning nil.
	err := env.handler.LoadProviders(context.Background())
	if err != nil {
		t.Errorf("LoadProviders should return nil even with decrypt error: %v", err)
	}
}

// ============================================================
// ShowCreate with default MFA provider set (line 150-152)
// ============================================================

// TestIDPShowCreate_WithDefaultMFAProvider covers the defaultMFAIDPtr != nil branch
// in ShowCreate (admin_idp.go lines 150-152).
func TestIDPShowCreate_WithDefaultMFAProvider(t *testing.T) {
	env := setupIDPTest(t)

	// Create an MFA provider and set it as default so defaultMFAIDPtr is non-nil.
	mfaRecord := &db.MFAProviderRecord{
		ID:           "test-mfa-for-create",
		Name:         "Test MFA",
		ProviderType: "email",
		Enabled:      true,
		ConfigJSON:   `{"otp_length":6,"otp_ttl_minutes":5}`,
	}
	if err := env.db.CreateMFAProvider(context.Background(), mfaRecord); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}
	id := mfaRecord.ID
	if err := env.db.SetDefaultMFAProviderID(context.Background(), &id); err != nil {
		t.Fatalf("setting default MFA: %v", err)
	}

	cookies := env.createAdminSession(t)
	rec := env.serveWithAdminSession(t, env.handler.ShowCreate, http.MethodGet, "/admin/idp/new", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ============================================================
// Update with all audit-change fields modified (lines 524-545)
// ============================================================

// TestIDPUpdate_AllAuditFieldChanges covers audit log change summary branches for
// fields that standard TestIDPUpdate does not change: group_search_base, tls_skip_verify,
// send_notification, notification_email_attr, password_complexity_hint, and
// service_account_username.
func TestIDPUpdate_AllAuditFieldChanges(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	// Insert an IDP with non-default field values.
	origCfg := idp.Config{
		Endpoint:               "ldap.example.com:389",
		Protocol:               "ldap",
		BaseDN:                 "dc=example,dc=com",
		UserSearchBase:         "ou=Users,dc=example,dc=com",
		GroupSearchBase:        "ou=Groups,dc=example,dc=com",
		TLSSkipVerify:          true,
		SendNotification:       true,
		NotificationEmailAttr:  "mail",
		PasswordComplexityHint: "at least 8 chars",
		Timeout:                10,
	}
	origCfgJSON, _ := json.Marshal(origCfg)
	origSecrets := idp.Secrets{
		ServiceAccountUsername: "old-service-user",
		ServiceAccountPassword: "old-service-pass",
	}
	origSecretsJSON, _ := json.Marshal(origSecrets)
	origBlob, err := env.crypto.Encrypt(origSecretsJSON)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	const idpID = "audit-fields-idp"
	record := &db.IdentityProviderRecord{
		ID:           idpID,
		FriendlyName: "Audit Fields IDP",
		Description:  "original desc",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(origCfgJSON),
		SecretBlob:   origBlob,
	}
	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	// Update with different values for all the audit-change fields.
	form := url.Values{}
	form.Set("friendly_name", "Audit Fields IDP") // same name, no name change
	form.Set("description", "original desc")      // same desc
	form.Set("provider_type", "ad")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	form.Set("base_dn", "dc=example,dc=com")
	form.Set("user_search_base", "ou=Users,dc=example,dc=com")
	form.Set("group_search_base", "ou=NewGroups,dc=example,dc=com") // CHANGE
	// tls_skip_verify was true; omitting it means false → CHANGE
	form.Set("send_notification", "")                        // omit/false → CHANGE (was true)
	form.Set("notification_email_attr", "email")             // CHANGE from "mail"
	form.Set("password_complexity_hint", "12 char minimum")  // CHANGE
	form.Set("service_account_username", "new-service-user") // CHANGE
	form.Set("service_account_password", "new-service-pass") // provided → covers changed password log
	form.Set("timeout", "10")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.Update(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/"+idpID, cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ============================================================
// Update with mfa_provider_id set (line 457-459)
// ============================================================

// TestIDPUpdate_WithMFAProviderID covers the record.MFAProviderID = &v branch
// when mfa_provider_id is non-empty in the Update form (admin_idp.go line 457-459).
func TestIDPUpdate_WithMFAProviderID(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDP(t)

	// Create an MFA provider to reference.
	mfaRecord := &db.MFAProviderRecord{
		ID:           "mfa-for-update",
		Name:         "MFA For Update",
		ProviderType: "email",
		Enabled:      true,
		ConfigJSON:   `{"otp_length":6,"otp_ttl_minutes":5}`,
	}
	if err := env.db.CreateMFAProvider(context.Background(), mfaRecord); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}

	form := url.Values{}
	form.Set("friendly_name", "Test IDP Updated")
	form.Set("provider_type", "ad")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	form.Set("base_dn", "dc=example,dc=com")
	form.Set("user_search_base", "ou=Users,dc=example,dc=com")
	form.Set("timeout", "10")
	form.Set("mfa_provider_id", mfaRecord.ID) // non-empty → covers line 458

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.Update(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/"+idpID, cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ============================================================
// Toggle when registerProvider fails (line 631)
// ============================================================

// TestIDPToggle_RegisterFails covers the branch where Toggle enables an IDP but
// registerProvider fails softly (admin_idp.go line 630-632). The handler should
// still redirect successfully.
func TestIDPToggle_RegisterFails(t *testing.T) {
	database := setupTestDB(t)

	// Insert a real IDP so ToggleIDP succeeds on the real DB.
	realCfg := idp.Config{Endpoint: "ldap.example.com:389", Protocol: "ldap", BaseDN: "dc=example,dc=com", Timeout: 10}
	realCfgJSON, _ := json.Marshal(realCfg)
	realRecord := &db.IdentityProviderRecord{
		ID: "toggle-register-fail", FriendlyName: "Toggle Test", ProviderType: "ad",
		Enabled: false, ConfigJSON: string(realCfgJSON),
	}
	if err := database.CreateIDP(context.Background(), realRecord); err != nil {
		t.Fatalf("creating real IDP: %v", err)
	}

	// Mock GetIDP to return fake record with unsupported provider type so registerProvider fails.
	fakeRecord := &db.IdentityProviderRecord{
		ID: "toggle-register-fail", Enabled: false, ProviderType: "unknown_xyz", ConfigJSON: "{}",
	}
	mock := &mockIDPErrStore{DB: database, getIDPRecord: fakeRecord}
	env := newIDPMockEnv(t, database, mock)
	cookies := env.createAdminSession(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "toggle-register-fail")
		env.handler.Toggle(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/toggle-register-fail/toggle", cookies, "")

	// registerProvider fails (unsupported type) but Toggle still redirects.
	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 even with registerProvider failure, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ============================================================
// parseAttributeMappings: empty row is skipped (line 1208-1209)
// ============================================================

// TestIDPCreate_WithEmptyMappingRow covers the continue branch in parseAttributeMappings
// when canonical_name[] or directory_attr[] entries are empty (admin_idp.go line 1208-1209).
func TestIDPCreate_WithEmptyMappingRow(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("id", "idp-empty-mapping")
	form.Set("friendly_name", "IDP Empty Mapping")
	form.Set("provider_type", "ad")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	form.Set("base_dn", "dc=example,dc=com")
	form.Set("user_search_base", "ou=Users,dc=example,dc=com")
	form.Set("timeout", "10")
	// Add one valid mapping row and one empty row.
	form["canonical_name[]"] = []string{"email", ""}          // second is empty → skipped
	form["directory_attr[]"] = []string{"mail", "samAccount"} // first is valid

	rec := env.serveWithAdminSession(t, env.handler.Create, http.MethodPost, "/admin/idp", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ============================================================
// parseCorrelationRule: empty match_mode defaults to "exact" (line 1231-1233)
// ============================================================

// TestIDPCreate_WithDefaultMatchMode covers the default match_mode branch in
// parseCorrelationRule when match_mode is empty (admin_idp.go lines 1231-1233).
func TestIDPCreate_WithDefaultMatchMode(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("id", "idp-default-match-mode")
	form.Set("friendly_name", "IDP Default Match Mode")
	form.Set("provider_type", "ad")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	form.Set("base_dn", "dc=example,dc=com")
	form.Set("user_search_base", "ou=Users,dc=example,dc=com")
	form.Set("timeout", "10")
	form.Set("source_canonical_attr", "email") // non-empty triggers rule creation
	// match_mode deliberately omitted → defaults to "exact"

	rec := env.serveWithAdminSession(t, env.handler.Create, http.MethodPost, "/admin/idp", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ============================================================
// ShowEdit: ListAttributeMappings error (soft error, line 329-331)
// ============================================================

// TestIDPShowEdit_ListAttributeMappingsError covers the soft error when
// ListAttributeMappings fails in ShowEdit (admin_idp.go lines 329-331).
// The handler logs the error but still renders the form (200).
func TestIDPShowEdit_ListAttributeMappingsError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockIDPErrStore{
		DB:                       database,
		listAttributeMappingsErr: fmt.Errorf("DB read failed"),
	}
	env := newIDPMockEnv(t, database, mock)
	cookies := env.createAdminSession(t)

	// Create a real IDP so GetIDP succeeds.
	record := &db.IdentityProviderRecord{
		ID: "idp-list-attr-err", FriendlyName: "Attr Err IDP", ProviderType: "ad",
		Enabled: true, ConfigJSON: `{"endpoint":"ldap.example.com:389","protocol":"ldap","base_dn":"dc=example,dc=com","timeout":10}`,
	}
	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", record.ID)
		env.handler.ShowEdit(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/"+record.ID+"/edit", cookies, "")

	// ListAttributeMappings error is soft (just logs) → form still renders with 200.
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 even with ListAttributeMappings error, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ============================================================
// Create soft error paths (SetAttributeMappings, SetCorrelationRule)
// ============================================================

// TestIDPCreate_SetAttributeMappingsError covers Create when SetAttributeMappings
// fails (soft error — admin_idp.go line 258).
func TestIDPCreate_SetAttributeMappingsError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockIDPErrStore{DB: database, setAttributeMappingsErr: fmt.Errorf("DB write failed")}
	env := newIDPMockEnv(t, database, mock)
	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("id", "idp-create-attrmap-err")
	form.Set("friendly_name", "Test IDP Attr")
	form.Set("provider_type", "ad")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	form.Set("base_dn", "dc=example,dc=com")
	form.Set("user_search_base", "ou=Users,dc=example,dc=com")
	form.Set("timeout", "10")
	// Add attribute mappings to trigger SetAttributeMappings call.
	form.Add("canonical_name[]", "firstname")
	form.Add("directory_attr[]", "givenName")

	rec := env.serveWithAdminSession(t, env.handler.Create, http.MethodPost, "/admin/idp", cookies, form.Encode())

	// Soft error: redirects to /admin/idp.
	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 (soft error on SetAttributeMappings), got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestIDPCreate_SetCorrelationRuleError covers Create when SetCorrelationRule
// fails (soft error — admin_idp.go line 266).
func TestIDPCreate_SetCorrelationRuleError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockIDPErrStore{DB: database, setCorrelationRuleErr: fmt.Errorf("DB write failed")}
	env := newIDPMockEnv(t, database, mock)
	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("id", "idp-create-corrule-err")
	form.Set("friendly_name", "Test IDP Corr")
	form.Set("provider_type", "ad")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	form.Set("base_dn", "dc=example,dc=com")
	form.Set("user_search_base", "ou=Users,dc=example,dc=com")
	form.Set("timeout", "10")
	// Add correlation rule to trigger SetCorrelationRule call.
	form.Set("source_canonical_attr", "email")

	rec := env.serveWithAdminSession(t, env.handler.Create, http.MethodPost, "/admin/idp", cookies, form.Encode())

	// Soft error: redirects to /admin/idp.
	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 (soft error on SetCorrelationRule), got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ============================================================
// Update soft error paths (SetAttributeMappings, SetCorrelationRule, audit diffs)
// ============================================================

// TestIDPUpdate_SetAttributeMappingsError covers Update when SetAttributeMappings
// fails (soft error — admin_idp.go line 471).
func TestIDPUpdate_SetAttributeMappingsError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockIDPErrStore{DB: database, setAttributeMappingsErr: fmt.Errorf("DB write failed")}
	env := newIDPMockEnv(t, database, mock)
	cookies := env.createAdminSession(t)

	// Create an IDP to update.
	idpID := env.createTestIDP(t)

	form := url.Values{}
	form.Set("friendly_name", "Updated IDP")
	form.Set("provider_type", "ad")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	form.Set("base_dn", "dc=example,dc=com")
	form.Set("user_search_base", "ou=Users,dc=example,dc=com")
	form.Set("timeout", "10")
	form.Add("canonical_name[]", "lastname")
	form.Add("directory_attr[]", "sn")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.Update(w, r)
	})
	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/"+idpID, cookies, form.Encode())

	// Soft error: still redirects to /admin/idp.
	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 (soft error on SetAttributeMappings), got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestIDPUpdate_SetCorrelationRuleError covers Update when SetCorrelationRule
// fails (soft error — admin_idp.go line 478).
func TestIDPUpdate_SetCorrelationRuleError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockIDPErrStore{DB: database, setCorrelationRuleErr: fmt.Errorf("DB write failed")}
	env := newIDPMockEnv(t, database, mock)
	cookies := env.createAdminSession(t)

	// Create an IDP to update.
	idpID := env.createTestIDP(t)

	form := url.Values{}
	form.Set("friendly_name", "Updated IDP")
	form.Set("provider_type", "ad")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	form.Set("base_dn", "dc=example,dc=com")
	form.Set("user_search_base", "ou=Users,dc=example,dc=com")
	form.Set("timeout", "10")
	form.Set("source_canonical_attr", "email")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.Update(w, r)
	})
	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/"+idpID, cookies, form.Encode())

	// Soft error: still redirects.
	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 (soft error on SetCorrelationRule), got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestIDPUpdate_LogoChange covers auditing when the logo URL changes
// (admin_idp.go line 509-510). Submitting remove_logo=1 clears the existing logo URL.
func TestIDPUpdate_LogoChange(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	// Insert an IDP with a non-empty LogoURL directly.
	cfgJSON, _ := json.Marshal(idp.Config{
		Endpoint:       "ldap.example.com:389",
		Protocol:       "ldap",
		BaseDN:         "dc=example,dc=com",
		UserSearchBase: "ou=Users,dc=example,dc=com",
		Timeout:        10,
	})
	record := &db.IdentityProviderRecord{
		ID:           "logo-change-idp",
		FriendlyName: "Logo IDP",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(cfgJSON),
		LogoURL:      "/uploads/old-logo.png",
	}
	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	form := url.Values{}
	form.Set("friendly_name", "Logo IDP")
	form.Set("provider_type", "ad")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	form.Set("base_dn", "dc=example,dc=com")
	form.Set("user_search_base", "ou=Users,dc=example,dc=com")
	form.Set("timeout", "10")
	form.Set("remove_logo", "1")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", record.ID)
		env.handler.Update(w, r)
	})
	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/"+record.ID, cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 on logo removal update, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestIDPUpdate_BaseDNChange covers auditing when base_dn changes
// (admin_idp.go line 518-519).
func TestIDPUpdate_BaseDNChange(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	idpID := env.createTestIDP(t)

	form := url.Values{}
	form.Set("friendly_name", "Test IDP")
	form.Set("provider_type", "ad")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	// Different base_dn from the original "dc=example,dc=com".
	form.Set("base_dn", "dc=changed,dc=com")
	form.Set("user_search_base", "ou=Users,dc=example,dc=com")
	form.Set("timeout", "10")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.Update(w, r)
	})
	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/"+idpID, cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 on base_dn change update, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestIDPUpdate_NoFieldChanges covers the "no field changes" audit path
// (admin_idp.go lines 553-554) when all submitted values match the original.
func TestIDPUpdate_NoFieldChanges(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	idpID := env.createTestIDP(t)

	// Submit exactly the same values as when the IDP was created.
	form := url.Values{}
	form.Set("friendly_name", "Test IDP")
	form.Set("description", "Test identity provider")
	form.Set("provider_type", "ad")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	form.Set("base_dn", "dc=example,dc=com")
	form.Set("user_search_base", "ou=Users,dc=example,dc=com")
	form.Set("timeout", "10")
	// Do NOT set service_account_password (leave blank so "changed" is not triggered).

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.Update(w, r)
	})
	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/"+idpID, cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 on no-change update, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ============================================================
// TestConnectionFromForm — remaining paths
// ============================================================

// TestIDPTestConnectionFromForm_ParseFormError covers TestConnectionFromForm when
// ParseForm fails (admin_idp.go lines 760-765).
func TestIDPTestConnectionFromForm_ParseFormError(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/idp/test-connection", errReader{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	wrapped := env.sm.Middleware(http.HandlerFunc(env.handler.TestConnectionFromForm))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for ParseForm error, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestIDPTestConnectionFromForm_GetIDPError covers TestConnectionFromForm when
// GetIDP fails (soft error — admin_idp.go line 801). The handler logs and continues.
func TestIDPTestConnectionFromForm_GetIDPError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockIDPErrStore{DB: database, getIDPErr: fmt.Errorf("not found")}
	env := newIDPMockEnv(t, database, mock)
	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("id", "nonexistent-idp")
	form.Set("provider_type", "ad")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	// No credentials — triggers the GetIDP fallback, which fails (soft error).
	// Then handler returns "credentials required" error.

	rec := env.serveWithAdminSession(t, env.handler.TestConnectionFromForm, http.MethodPost, "/admin/idp/test-connection", cookies, form.Encode())

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 (credentials required after GetIDP error), got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ============================================================
// handleLogoUpload — os.Create error path
// ============================================================

// TestIDPHandleLogoUpload_CreateError covers handleLogoUpload when os.Create fails
// because uploadsDir is non-existent (admin_idp.go lines 89-91).
func TestIDPHandleLogoUpload_CreateError(t *testing.T) {
	env := setupIDPTest(t)

	// Create a new handler with an invalid uploadsDir so os.Create always fails.
	invalidDir := "/nonexistent/directory/that/does/not/exist"
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	key, _ := crypto.GenerateKey()
	cryptoSvc, _ := crypto.NewService(key, 1)
	tmpFile, _ := os.CreateTemp(t.TempDir(), "audit-*.log")
	_ = tmpFile.Close()
	auditLog, err := audit.NewLogger(env.db, tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("creating audit logger: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })
	h := NewAdminIDPHandler(env.db, cryptoSvc, env.registry, stubIDPRenderer(t), auditLog, logger, invalidDir)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("logo_file", "logo.png")
	if err != nil {
		t.Fatalf("creating form file: %v", err)
	}
	io.WriteString(fw, "fake png data") //nolint:errcheck
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if err := req.ParseMultipartForm(5 << 20); err != nil {
		t.Fatalf("parsing multipart form: %v", err)
	}

	// handleLogoUpload should fail at os.Create and return the currentLogoURL.
	currentURL := "/uploads/existing-logo.png"
	result := h.handleLogoUpload(req, "test-idp", currentURL)
	if result != currentURL {
		t.Errorf("expected currentLogoURL %q when os.Create fails, got %q", currentURL, result)
	}
}

// buildLogoUploadRequest creates a multipart request containing a logo file.
func buildLogoUploadRequest(t *testing.T, filename string, content []byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("logo_file", filename)
	if err != nil {
		t.Fatalf("creating form file: %v", err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatalf("writing file content: %v", err)
	}
	_ = w.Close()
	req := httptest.NewRequest(http.MethodPost, "/admin/idp/test-idp/logo", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req
}

func TestUploadLogo_Success(t *testing.T) {
	env := setupIDPTest(t)
	idpID := env.createTestIDP(t)

	req := buildLogoUploadRequest(t, "logo.png", []byte("fake-png-data"))
	req = withChiURLParam(req, "id", idpID)

	rec := httptest.NewRecorder()
	env.handler.UploadLogo(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response JSON: %v", err)
	}
	logoURL, ok := resp["logo_url"]
	if !ok || logoURL == "" {
		t.Errorf("expected logo_url in response, got: %v", resp)
	}
}

func TestUploadLogo_IDPNotFound(t *testing.T) {
	env := setupIDPTest(t)

	req := buildLogoUploadRequest(t, "logo.png", []byte("data"))
	req = withChiURLParam(req, "id", "nonexistent-idp")

	rec := httptest.NewRecorder()
	env.handler.UploadLogo(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown IDP, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestUploadLogo_NoFileProvided(t *testing.T) {
	env := setupIDPTest(t)
	idpID := env.createTestIDP(t)

	// Multipart form without a file field.
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("other_field", "value")
	_ = w.Close()
	req := httptest.NewRequest(http.MethodPost, "/admin/idp/"+idpID+"/logo", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req = withChiURLParam(req, "id", idpID)

	rec := httptest.NewRecorder()
	env.handler.UploadLogo(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing file, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestUploadLogo_InvalidExtension(t *testing.T) {
	env := setupIDPTest(t)
	idpID := env.createTestIDP(t)

	req := buildLogoUploadRequest(t, "logo.exe", []byte("malware"))
	req = withChiURLParam(req, "id", idpID)

	rec := httptest.NewRecorder()
	env.handler.UploadLogo(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid extension, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestUploadLogo_InvalidMultipart(t *testing.T) {
	env := setupIDPTest(t)
	idpID := env.createTestIDP(t)

	// Not a multipart form at all.
	req := httptest.NewRequest(http.MethodPost, "/admin/idp/"+idpID+"/logo",
		strings.NewReader("not multipart"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withChiURLParam(req, "id", idpID)

	rec := httptest.NewRecorder()
	env.handler.UploadLogo(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid multipart, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestUploadLogo_ReplacesOldLogo(t *testing.T) {
	env := setupIDPTest(t)
	idpID := env.createTestIDP(t)

	uploadsDir := env.handler.uploadsDir

	// Pre-create an "old" logo file with a different extension.
	oldLogo := "idp-logo-" + idpID + ".jpg"
	oldPath := uploadsDir + "/" + oldLogo
	if err := os.WriteFile(oldPath, []byte("old jpg"), 0640); err != nil {
		t.Fatalf("writing old logo: %v", err)
	}
	// Set the IDP's current logo URL to the old file.
	ctx := context.Background()
	record, _ := env.db.GetIDP(ctx, idpID)
	record.LogoURL = "/uploads/" + oldLogo
	_ = env.db.UpdateIDP(ctx, record)

	// Upload a new PNG logo.
	req := buildLogoUploadRequest(t, "logo.png", []byte("new png data"))
	req = withChiURLParam(req, "id", idpID)

	rec := httptest.NewRecorder()
	env.handler.UploadLogo(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Old file should have been removed.
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Error("expected old logo to be removed after upload")
	}
}

// TestUploadLogo_SaveFailure triggers the os.Create error path by using an
// invalid uploads directory that does not exist.
func TestUploadLogo_SaveFailure(t *testing.T) {
	env := setupIDPTest(t)
	idpID := env.createTestIDP(t)

	// Rebuild handler with a non-existent uploads dir so os.Create always fails.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	key, _ := crypto.GenerateKey()
	cryptoSvc, _ := crypto.NewService(key, 1)
	tmpFile, _ := os.CreateTemp(t.TempDir(), "audit-*.log")
	_ = tmpFile.Close()
	auditLog, err := audit.NewLogger(env.db, tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("creating audit logger: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })

	badHandler := NewAdminIDPHandler(
		env.db, cryptoSvc, env.registry,
		stubIDPRenderer(t), auditLog, logger,
		"/nonexistent/uploads/dir/that/cannot/be/created",
	)

	req := buildLogoUploadRequest(t, "logo.png", []byte("some png data"))
	req = withChiURLParam(req, "id", idpID)

	rec := httptest.NewRecorder()
	badHandler.UploadLogo(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when os.Create fails, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestUploadLogo_UpdateIDPError covers the UpdateIDP error path in UploadLogo.
func TestUploadLogo_UpdateIDPError(t *testing.T) {
	database := setupTestDB(t)

	// Create an IDP record in the real DB so GetIDP succeeds.
	env := setupIDPTest(t)
	idpID := env.createTestIDP(t)

	// Rebuild with mock store that will fail on UpdateIDP.
	mock := &mockIDPErrStore{
		DB:           database,
		updateIDPErr: fmt.Errorf("DB write failed"),
	}
	// The mock needs the IDP that was created in env.db, not in database.
	// Use getIDPRecord override to return the IDP without touching the DB.
	idpRec, err := env.db.GetIDP(context.Background(), idpID)
	if err != nil {
		t.Fatalf("getting created IDP: %v", err)
	}
	mock.getIDPRecord = idpRec

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	key, _ := crypto.GenerateKey()
	cryptoSvc, _ := crypto.NewService(key, 1)
	tmpFile, _ := os.CreateTemp(t.TempDir(), "audit-*.log")
	_ = tmpFile.Close()
	auditLog, err := audit.NewLogger(database, tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("creating audit logger: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })

	h := NewAdminIDPHandler(mock, cryptoSvc, env.registry, stubIDPRenderer(t), auditLog, logger, t.TempDir())

	req := buildLogoUploadRequest(t, "logo.png", []byte("png data"))
	req = withChiURLParam(req, "id", idpID)

	rec := httptest.NewRecorder()
	h.UploadLogo(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when UpdateIDP fails, got %d; body: %s", rec.Code, rec.Body.String())
	}
}
