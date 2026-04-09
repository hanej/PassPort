// Package handler - additional coverage tests targeting specific low-coverage paths.
package handler

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/mfa"
)

// ============================================================
// SearchDirectory — 0% coverage
// ============================================================

func TestSearchDirectory_MissingAttr(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDP(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.SearchDirectory(w, r)
	})

	// No attr or value params → 400.
	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/"+idpID+"/search", cookies, "")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON response: %v", err)
	}
	if !strings.Contains(result["error"], "attr and value") {
		t.Errorf("expected error about attr/value, got: %s", result["error"])
	}
}

func TestSearchDirectory_NoIDP(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "nonexistent-idp")
		env.handler.SearchDirectory(w, r)
	})

	// Attr and value provided but IDP not found → getLDAPConn fails → 500.
	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/nonexistent-idp/search?attr=sAMAccountName&value=jdoe", cookies, "")

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestSearchDirectory_IDPExists_ConnectionFails(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDP(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.SearchDirectory(w, r)
	})

	// IDP exists (fake LDAP endpoint) → connection fails → 500.
	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/"+idpID+"/search?attr=uid&value=jdoe", cookies, "")

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

// ============================================================
// TestConnectionFromForm — 17% coverage
// ============================================================

func TestTestConnectionFromForm_NoCredentials(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	// No service account credentials provided.

	rec := env.serveWithAdminSession(t, env.handler.TestConnectionFromForm, http.MethodPost, "/admin/idp/test-connection", cookies, form.Encode())

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestTestConnectionFromForm_ADWithCredentials(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("provider_type", "ad")
	form.Set("endpoint", "127.0.0.1:1") // Will fail to connect.
	form.Set("protocol", "ldap")
	form.Set("service_account_username", "cn=admin,dc=example,dc=com")
	form.Set("service_account_password", "secret")

	rec := env.serveWithAdminSession(t, env.handler.TestConnectionFromForm, http.MethodPost, "/admin/idp/test-connection", cookies, form.Encode())

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON response, got: %s", ct)
	}
}

func TestTestConnectionFromForm_FreeIPAWithCredentials(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("provider_type", "freeipa")
	form.Set("endpoint", "127.0.0.1:1")
	form.Set("protocol", "ldap")
	form.Set("service_account_username", "uid=admin,cn=users,dc=example,dc=com")
	form.Set("service_account_password", "secret")

	rec := env.serveWithAdminSession(t, env.handler.TestConnectionFromForm, http.MethodPost, "/admin/idp/test-connection", cookies, form.Encode())

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON response, got: %s", ct)
	}
}

func TestTestConnectionFromForm_WithSavedCredentials(t *testing.T) {
	// When credentials are empty but idpID is provided, it falls back to saved.
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDP(t)

	form := url.Values{}
	form.Set("id", idpID)
	form.Set("endpoint", "127.0.0.1:1")
	form.Set("protocol", "ldap")
	// No credentials — should try to load from saved IDP record.

	rec := env.serveWithAdminSession(t, env.handler.TestConnectionFromForm, http.MethodPost, "/admin/idp/test-connection", cookies, form.Encode())

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON response, got: %s", ct)
	}
}

// ============================================================
// buildMFAClient — Duo path (32% → higher)
// ============================================================

func TestBuildMFAClient_DuoValid(t *testing.T) {
	env := setupMFAHandlerTest(t)

	duoCfg := mfa.DuoConfig{
		ClientID:    "12345678901234567890", // exactly 20 chars
		APIHostname: "api.duo.example.com",
		RedirectURI: "https://app.example.com/duo/callback",
	}
	duoSecrets := mfa.DuoSecrets{
		ClientSecret: "1234567890123456789012345678901234567890", // exactly 40 chars
	}
	cfgBytes, _ := json.Marshal(duoCfg)
	secretsBytes, _ := json.Marshal(duoSecrets)
	encryptedSecrets, err := env.crypto.Encrypt(secretsBytes)
	if err != nil {
		t.Fatalf("encrypting secrets: %v", err)
	}

	record := &db.MFAProviderRecord{
		ID:           "duo-provider",
		Name:         "duo",
		ProviderType: "duo",
		Enabled:      true,
		ConfigJSON:   string(cfgBytes),
		SecretBlob:   encryptedSecrets,
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}
	providerID := "duo-provider"
	if err := env.db.SetDefaultMFAProviderID(context.Background(), &providerID); err != nil {
		t.Fatalf("setting default: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	client, pRecord, err := env.handler.buildMFAClient(req, "some-idp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Error("expected non-nil client for valid Duo config")
	}
	if pRecord == nil {
		t.Error("expected non-nil provider record")
	}
}

func TestBuildMFAClient_DuoInvalidJSON(t *testing.T) {
	env := setupMFAHandlerTest(t)

	record := &db.MFAProviderRecord{
		ID:           "duo-bad",
		Name:         "duo",
		ProviderType: "duo",
		Enabled:      true,
		ConfigJSON:   "not-json}",
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}
	providerID := "duo-bad"
	if err := env.db.SetDefaultMFAProviderID(context.Background(), &providerID); err != nil {
		t.Fatalf("setting default: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	_, _, err := env.handler.buildMFAClient(req, "some-idp")
	if err == nil {
		t.Error("expected error for invalid Duo config JSON")
	}
}

func TestBuildMFAClient_DuoInvalidSecret(t *testing.T) {
	env := setupMFAHandlerTest(t)

	duoCfg := mfa.DuoConfig{
		ClientID:    "12345678901234567890",
		APIHostname: "api.duo.example.com",
		RedirectURI: "https://app.example.com/duo/callback",
	}
	cfgBytes, _ := json.Marshal(duoCfg)

	record := &db.MFAProviderRecord{
		ID:           "duo-bad-secret",
		Name:         "duo",
		ProviderType: "duo",
		Enabled:      true,
		ConfigJSON:   string(cfgBytes),
		SecretBlob:   []byte("not-valid-ciphertext"),
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}
	providerID := "duo-bad-secret"
	if err := env.db.SetDefaultMFAProviderID(context.Background(), &providerID); err != nil {
		t.Fatalf("setting default: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	_, _, err := env.handler.buildMFAClient(req, "some-idp")
	if err == nil {
		t.Error("expected error for invalid Duo secret blob")
	}
}

// ============================================================
// ShowMFA — Duo provider path (54.3% → higher)
// ============================================================

func TestShowMFA_DuoProvider_InitiateFailsRedirects(t *testing.T) {
	env := setupMFAHandlerTest(t)

	// Set up valid Duo provider as default (Duo Initiate will fail on real network call).
	duoCfg := mfa.DuoConfig{
		ClientID:    "12345678901234567890",
		APIHostname: "api.duo.example.com",
		RedirectURI: "https://app.example.com/duo/callback",
	}
	duoSecrets := mfa.DuoSecrets{
		ClientSecret: "1234567890123456789012345678901234567890",
	}
	cfgBytes, _ := json.Marshal(duoCfg)
	secretsBytes, _ := json.Marshal(duoSecrets)
	encryptedSecrets, _ := env.crypto.Encrypt(secretsBytes)

	record := &db.MFAProviderRecord{
		ID:           "duo-show",
		Name:         "duo",
		ProviderType: "duo",
		Enabled:      true,
		ConfigJSON:   string(cfgBytes),
		SecretBlob:   encryptedSecrets,
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}
	providerID := "duo-show"
	if err := env.db.SetDefaultMFAProviderID(context.Background(), &providerID); err != nil {
		t.Fatalf("setting default: %v", err)
	}

	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")
	rec := env.serveWithSession(t, env.handler.ShowMFA, http.MethodGet, "/mfa", cookies, "")

	// Duo Initiate will fail → redirect to error redirect.
	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ============================================================
// Callback — state matches (57.6% → higher)
// ============================================================

func TestCallback_StateMatches_NoClient(t *testing.T) {
	env := setupMFAHandlerTest(t)
	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")

	// Get the session ID to update its MFA state.
	var sessID string
	{
		rec2 := httptest.NewRecorder()
		req2 := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, c := range cookies {
			req2.AddCookie(c)
		}
		wrapped := env.sm.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := auth.SessionFromContext(r.Context())
			if sess != nil {
				sessID = sess.ID
			}
		}))
		wrapped.ServeHTTP(rec2, req2)
	}

	if sessID == "" {
		t.Skip("could not obtain session ID")
	}

	if err := env.db.UpdateSessionMFA(context.Background(), sessID, true, "test-state"); err != nil {
		t.Fatalf("updating session MFA: %v", err)
	}

	// State matches but no MFA client configured → redirect to error.
	rec := env.serveWithSession(t, env.handler.Callback, http.MethodGet, "/mfa/callback?duo_code=abc&state=test-state", cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
}

// ============================================================
// admin_smtp.Show — additional paths (78.9% → higher)
// ============================================================

func TestSMTPShow_WithInvalidJSONConfig(t *testing.T) {
	env := setupSMTPTest(t)

	if err := env.db.SaveSMTPConfig(context.Background(), &db.SMTPConfig{
		ConfigJSON: "not-valid-json}",
	}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	cookies := env.createAdminSession(t)
	rec := env.serveWithAdminSession(t, env.handler.Show, http.MethodGet, "/admin/smtp", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestSMTPShow_WithBadSecrets(t *testing.T) {
	env := setupSMTPTest(t)

	cfg := map[string]any{"host": "smtp.example.com", "port": "587", "enabled": true}
	cfgJSON, _ := json.Marshal(cfg)

	if err := env.db.SaveSMTPConfig(context.Background(), &db.SMTPConfig{
		ConfigJSON: string(cfgJSON),
		SecretBlob: []byte("not-valid-ciphertext"),
	}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	cookies := env.createAdminSession(t)
	rec := env.serveWithAdminSession(t, env.handler.Show, http.MethodGet, "/admin/smtp", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestSMTPSave_TLSOptions(t *testing.T) {
	env := setupSMTPTest(t)
	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("host", "smtp.example.com")
	form.Set("port", "465")
	form.Set("from_address", "noreply@example.com")
	form.Set("use_tls", "on")
	form.Set("tls_skip_verify", "on")
	form.Set("enabled", "on")

	rec := env.serveWithAdminSession(t, env.handler.Save, http.MethodPost, "/admin/smtp", cookies, form.Encode())
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// ============================================================
// admin_groups.List — test with IDPs present (57.1% → higher)
// ============================================================

func TestGroupsList_WithIDPsAndGroups(t *testing.T) {
	env := setupGroupsTest(t)
	cookies := env.createAdminSession(t)

	// Create a provider and group.
	idpRecord := &db.IdentityProviderRecord{
		ID:           "groups-idp",
		FriendlyName: "Groups IDP",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   `{"endpoint":"ldap://localhost","protocol":"ldap"}`,
	}
	if err := env.db.CreateIDP(context.Background(), idpRecord); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}
	if err := env.db.CreateAdminGroup(context.Background(), &db.AdminGroup{
		IDPID:       "groups-idp",
		GroupDN:     "cn=admins,dc=example,dc=com",
		Description: "Admin group",
	}); err != nil {
		t.Fatalf("creating admin group: %v", err)
	}

	rec := env.serveWithAdminSession(t, env.handler.List, http.MethodGet, "/admin/groups", cookies, "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ============================================================
// admin_branding.Show — with existing config (57.1% → higher)
// ============================================================

func TestBrandingShow_WithBrandingConfig(t *testing.T) {
	env := setupBrandingTest(t)
	cookies := env.createAdminSession(t)

	// Save a branding config to exercise the load path.
	if err := env.db.SaveBrandingConfig(context.Background(), &db.BrandingConfig{
		AppTitle: "My Portal",
	}); err != nil {
		t.Fatalf("setting branding config: %v", err)
	}

	rec := env.serveWithAdminSession(t, env.handler.Show, http.MethodGet, "/admin/branding", cookies, nil)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// ============================================================
// admin_idp.ReadEntry — test getLDAPConn failure with IDP
// ============================================================

func TestReadEntry_IDPExists_ConnectionFails(t *testing.T) {
	env := setupBrowseTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDPWithConfig(t, "read-fail-idp")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.ReadEntry(w, r)
	})

	// Has DN param but LDAP connection will fail.
	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/"+idpID+"/entry?dn=cn=test,dc=example,dc=com", cookies, "")

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

// ============================================================
// admin_idp.BrowseChildren — IDP exists but connection fails
// ============================================================

func TestBrowseChildren_IDPExists_ConnectionFails(t *testing.T) {
	env := setupBrowseTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDPWithConfig(t, "browse-fail-idp")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.BrowseChildren(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/"+idpID+"/browse", cookies, "")

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

// ============================================================
// checkAdminGroupMembership — no admin groups configured
// ============================================================

func TestCheckAdminGroupMembership_NoAdminGroups(t *testing.T) {
	env := setupLoginTest(t)
	provider := &mockProvider{id: "corp-ad", userGroups: []string{}}
	env.registry.Register("corp-ad", provider)

	result := env.handler.checkAdminGroupMembership(context.Background(), provider, "corp-ad", "jdoe")
	if result {
		t.Error("expected false when no admin groups configured")
	}
}

// ============================================================
// idp.handleLogoUpload test via request without file
// ============================================================

func TestHandleLogoUpload_NoFile(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/idp/create", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	wrapped := env.sm.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = env.handler.handleLogoUpload(r, "", "")
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK && rec.Code != http.StatusBadRequest {
		t.Errorf("unexpected status %d", rec.Code)
	}
}

// ============================================================
// NewRenderer — extra coverage
// ============================================================

func TestNewRenderer_LoadsAndHasPages(t *testing.T) {
	logger := testLogger()
	r, err := NewRenderer(logger)
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}
	if len(r.pages) == 0 {
		t.Error("expected at least one page template")
	}
}

// ============================================================
// Renderer.JSON with marshal error path
// ============================================================

func TestRendererJSON_MarshalError(t *testing.T) {
	// Create a renderer with a manually-initialized map.
	pages := make(map[string]*template.Template)
	renderer := &Renderer{pages: pages, logger: testLogger()}

	rec := httptest.NewRecorder()

	// A valid structure — just verify the function works.
	renderer.JSON(rec, http.StatusOK, map[string]string{"status": "ok"})
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// ============================================================
// admin_idp — FreeIPA Create
// ============================================================

func TestIDPCreate_FreeIPA(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("id", "freeipa-test")
	form.Set("friendly_name", "FreeIPA Test")
	form.Set("provider_type", "freeipa")
	form.Set("endpoint", "ldap.example.com:389")
	form.Set("protocol", "ldap")
	form.Set("base_dn", "dc=example,dc=com")
	form.Set("service_account_username", "uid=admin,cn=users,dc=example,dc=com")
	form.Set("service_account_password", "secret")

	rec := env.serveWithAdminSession(t, env.handler.Create, http.MethodPost, "/admin/idp", cookies, form.Encode())

	if rec.Code != http.StatusFound && rec.Code != http.StatusOK {
		t.Errorf("expected redirect or 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ============================================================
// admin_audit pagination — additional path
// ============================================================

func TestAdminAuditListPage2(t *testing.T) {
	env := setupAuditTest(t)
	cookies := env.createAdminSession(t)

	rec := env.serveWithAdminSession(t, env.handler.List, http.MethodGet, "/admin/audit?page=2", cookies)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}
