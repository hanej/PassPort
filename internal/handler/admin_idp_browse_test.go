package handler

import (
	"context"
	"encoding/json"
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
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
)

type browseTestEnv struct {
	db      *db.DB
	crypto  *crypto.Service
	handler *AdminIDPHandler
	sm      *auth.SessionManager
	audit   *audit.Logger
}

func stubBrowseRenderer(t *testing.T) *Renderer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	funcMap := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"pages":    func(n int) []int { return nil },
	}
	pages := make(map[string]*template.Template)
	pages["admin_idp_browse.html"] = template.Must(template.New("admin_idp_browse.html").Funcs(funcMap).Parse(`{{define "base"}}browse page {{.Data.IDP.FriendlyName}} {{.Data.BaseDN}}{{end}}`))
	pages["admin_idp_list.html"] = template.Must(template.New("admin_idp_list.html").Funcs(funcMap).Parse(`{{define "base"}}idp list page{{end}}`))
	pages["admin_idp_form.html"] = template.Must(template.New("admin_idp_form.html").Funcs(funcMap).Parse(`{{define "base"}}idp form page{{end}}`))
	pages["error.html"] = template.Must(template.New("error.html").Funcs(funcMap).Parse(`{{define "base"}}error page{{end}}`))
	return &Renderer{pages: pages, logger: logger}
}

func setupBrowseTest(t *testing.T) *browseTestEnv {
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
	renderer := stubBrowseRenderer(t)

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

	h := NewAdminIDPHandler(database, cryptoSvc, registry, renderer, auditLog, logger, t.TempDir())

	return &browseTestEnv{
		db:      database,
		crypto:  cryptoSvc,
		handler: h,
		sm:      sm,
		audit:   auditLog,
	}
}

func (env *browseTestEnv) createAdminSession(t *testing.T) []*http.Cookie {
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

func (env *browseTestEnv) serveWithAdminSession(t *testing.T, handler http.HandlerFunc, method, path string, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
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

func (env *browseTestEnv) createTestIDPWithConfig(t *testing.T, id string) string {
	t.Helper()

	cfg := idp.Config{
		Endpoint:       "ldap.example.com:389",
		Protocol:       "ldap",
		BaseDN:         "dc=example,dc=com",
		UserSearchBase: "ou=Users,dc=example,dc=com",
		Timeout:        10,
		RetryCount:     1,
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
		ID:           id,
		FriendlyName: "Test IDP " + id,
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

func TestBrowsePage_Success(t *testing.T) {
	env := setupBrowseTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDPWithConfig(t, "browse-idp")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.BrowsePage(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/"+idpID+"/browse-page", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Test IDP browse-idp") {
		t.Errorf("expected IDP friendly name in response, got: %s", body)
	}
	if !strings.Contains(body, "dc=example,dc=com") {
		t.Errorf("expected BaseDN in response, got: %s", body)
	}
}

func TestBrowsePage_NotFound(t *testing.T) {
	env := setupBrowseTest(t)
	cookies := env.createAdminSession(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "nonexistent-idp")
		env.handler.BrowsePage(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/nonexistent-idp/browse-page", cookies, "")

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "error page") {
		t.Errorf("expected error page rendered, got: %s", rec.Body.String())
	}
}

func TestBrowseChildren_NoIDP(t *testing.T) {
	env := setupBrowseTest(t)
	cookies := env.createAdminSession(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "nonexistent-idp")
		env.handler.BrowseChildren(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/nonexistent-idp/browse", cookies, "")

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content type, got %s", ct)
	}

	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON response: %v", err)
	}
	if result["error"] == "" {
		t.Error("expected non-empty error message in JSON response")
	}
}

func TestReadEntry_MissingDN(t *testing.T) {
	env := setupBrowseTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDPWithConfig(t, "read-idp")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.ReadEntry(w, r)
	})

	// Request without dn query parameter
	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/"+idpID+"/entry", cookies, "")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content type, got %s", ct)
	}

	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON response: %v", err)
	}
	if !strings.Contains(result["error"], "dn query parameter is required") {
		t.Errorf("expected error about missing dn parameter, got: %s", result["error"])
	}
}
