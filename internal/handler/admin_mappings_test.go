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

type mappingsTestEnv struct {
	db      *db.DB
	handler *AdminMappingsHandler
	sm      *auth.SessionManager
	audit   *audit.Logger
}

func stubMappingsRenderer(t *testing.T) *Renderer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	funcMap := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"pages":    func(n int) []int { return nil },
	}
	pages := make(map[string]*template.Template)
	pages["admin_mappings.html"] = template.Must(template.New("admin_mappings.html").Funcs(funcMap).Parse(`{{define "base"}}mappings page{{end}}`))
	pages["error.html"] = template.Must(template.New("error.html").Funcs(funcMap).Parse(`{{define "base"}}error page{{end}}`))
	return &Renderer{pages: pages, logger: logger}
}

func setupMappingsTest(t *testing.T) *mappingsTestEnv {
	t.Helper()

	database := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := stubMappingsRenderer(t)

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

	registry := idp.NewRegistry(logger)
	h := NewAdminMappingsHandler(database, registry, renderer, auditLog, logger)

	return &mappingsTestEnv{
		db:      database,
		handler: h,
		sm:      sm,
		audit:   auditLog,
	}
}

func (env *mappingsTestEnv) createAdminSession(t *testing.T) []*http.Cookie {
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

func (env *mappingsTestEnv) serveWithAdminSession(t *testing.T, handler http.HandlerFunc, method, path string, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
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

func (env *mappingsTestEnv) createTestIDPAndMapping(t *testing.T) (string, int64) {
	t.Helper()

	record := &db.IdentityProviderRecord{
		ID:           "test-idp",
		FriendlyName: "Test IDP",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   "{}",
	}
	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating test IDP: %v", err)
	}

	mapping := &db.UserIDPMapping{
		AuthProviderID:  "local",
		AuthUsername:    "testuser",
		TargetIDPID:     "test-idp",
		TargetAccountDN: "cn=testuser,ou=Users,dc=example,dc=com",
		LinkType:        "auto",
		LinkedAt:        time.Now().UTC(),
	}
	if err := env.db.UpsertMapping(context.Background(), mapping); err != nil {
		t.Fatalf("creating test mapping: %v", err)
	}

	// Retrieve the mapping to get its ID.
	mappings, err := env.db.ListMappings(context.Background(), "local", "testuser")
	if err != nil {
		t.Fatalf("listing mappings: %v", err)
	}
	if len(mappings) == 0 {
		t.Fatal("expected at least one mapping")
	}

	return record.ID, mappings[0].ID
}

func TestMappingsShow(t *testing.T) {
	env := setupMappingsTest(t)
	cookies := env.createAdminSession(t)

	rec := env.serveWithAdminSession(t, env.handler.Show, http.MethodGet, "/admin/mappings", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "mappings page") {
		t.Errorf("expected mappings content, got: %s", rec.Body.String())
	}
}

func TestMappingsSearch(t *testing.T) {
	env := setupMappingsTest(t)
	cookies := env.createAdminSession(t)
	env.createTestIDPAndMapping(t)

	rec := env.serveWithAdminSession(t, env.handler.Search, http.MethodGet, "/admin/mappings/search?username=testuser&auth_provider_id=local", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestMappingsSearchMissingUsername(t *testing.T) {
	env := setupMappingsTest(t)
	cookies := env.createAdminSession(t)

	rec := env.serveWithAdminSession(t, env.handler.Search, http.MethodGet, "/admin/mappings/search", cookies, "")

	// Empty username is now valid — lists all mappings (same as "*").
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestMappingsSearchWildcardListsAll(t *testing.T) {
	env := setupMappingsTest(t)
	cookies := env.createAdminSession(t)
	env.createTestIDPAndMapping(t)

	// Both "*" and empty username should return the same all-mappings result.
	for _, username := range []string{"*", ""} {
		path := "/admin/mappings/search"
		if username != "" {
			path += "?username=" + username
		}
		rec := env.serveWithAdminSession(t, env.handler.Search, http.MethodGet, path, cookies, "")
		if rec.Code != http.StatusOK {
			t.Errorf("username=%q: expected 200, got %d", username, rec.Code)
		}
	}
}

func TestMappingsDelete(t *testing.T) {
	env := setupMappingsTest(t)
	cookies := env.createAdminSession(t)
	_, mappingID := env.createTestIDPAndMapping(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", fmt.Sprintf("%d", mappingID))
		env.handler.Delete(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, fmt.Sprintf("/admin/mappings/%d/delete", mappingID), cookies, "")

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify mapping was deleted.
	mappings, err := env.db.ListMappings(context.Background(), "local", "testuser")
	if err != nil {
		t.Fatalf("listing mappings: %v", err)
	}
	if len(mappings) != 0 {
		t.Errorf("expected 0 mappings after delete, got %d", len(mappings))
	}
}

func TestMappingsDeleteAll(t *testing.T) {
	env := setupMappingsTest(t)
	cookies := env.createAdminSession(t)
	env.createTestIDPAndMapping(t)

	form := url.Values{}
	form.Set("auth_provider_id", "local")
	form.Set("username", "testuser")

	rec := env.serveWithAdminSession(t, env.handler.DeleteAll, http.MethodPost, "/admin/mappings/delete-all", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify all mappings were deleted.
	mappings, err := env.db.ListMappings(context.Background(), "local", "testuser")
	if err != nil {
		t.Fatalf("listing mappings: %v", err)
	}
	if len(mappings) != 0 {
		t.Errorf("expected 0 mappings after delete-all, got %d", len(mappings))
	}
}

func TestMappingsDeleteAllMissingUsername(t *testing.T) {
	env := setupMappingsTest(t)
	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("auth_provider_id", "local")
	// Missing username

	rec := env.serveWithAdminSession(t, env.handler.DeleteAll, http.MethodPost, "/admin/mappings/delete-all", cookies, form.Encode())

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}
}

// --- DB error path tests ---

type mockMappingsErrStore struct {
	*db.DB
	listIDPsErr          error
	searchMappingsErr    error
	deleteMappingErr     error
	deleteAllMappingsErr error
}

func (m *mockMappingsErrStore) ListIDPs(ctx context.Context) ([]db.IdentityProviderRecord, error) {
	if m.listIDPsErr != nil {
		return nil, m.listIDPsErr
	}
	return m.DB.ListIDPs(ctx)
}

func (m *mockMappingsErrStore) SearchMappings(ctx context.Context, filter db.MappingSearchFilter) ([]db.UserIDPMapping, int, error) {
	if m.searchMappingsErr != nil {
		return nil, 0, m.searchMappingsErr
	}
	return m.DB.SearchMappings(ctx, filter)
}

func (m *mockMappingsErrStore) DeleteMapping(ctx context.Context, id int64) error {
	if m.deleteMappingErr != nil {
		return m.deleteMappingErr
	}
	return m.DB.DeleteMapping(ctx, id)
}

func (m *mockMappingsErrStore) DeleteAllMappings(ctx context.Context, authProviderID, authUsername string) (int64, error) {
	if m.deleteAllMappingsErr != nil {
		return 0, m.deleteAllMappingsErr
	}
	return m.DB.DeleteAllMappings(ctx, authProviderID, authUsername)
}

func newMappingsMockHandler(t *testing.T, mock *mockMappingsErrStore) *AdminMappingsHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	renderer := stubMappingsRenderer(t)

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

	registry := idp.NewRegistry(logger)
	return NewAdminMappingsHandler(mock, registry, renderer, auditLog, logger)
}

func TestAdminMappingsShow_ListIDPsError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockMappingsErrStore{DB: database, listIDPsErr: fmt.Errorf("db failure")}
	h := newMappingsMockHandler(t, mock)

	req := httptest.NewRequest(http.MethodGet, "/admin/mappings", nil)
	rec := httptest.NewRecorder()
	h.Show(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "error page") {
		t.Errorf("expected error page, got: %s", rec.Body.String())
	}
}

func TestAdminMappingsSearch_SearchMappingsError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockMappingsErrStore{DB: database, searchMappingsErr: fmt.Errorf("db failure")}
	h := newMappingsMockHandler(t, mock)

	req := httptest.NewRequest(http.MethodGet, "/admin/mappings/search?username=testuser", nil)
	rec := httptest.NewRecorder()
	h.Search(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "error page") {
		t.Errorf("expected error page, got: %s", rec.Body.String())
	}
}

func TestAdminMappingsDelete_InvalidID(t *testing.T) {
	env := setupMappingsTest(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/mappings/notanid/delete", nil)
	req = withChiURLParam(req, "id", "notanid")
	rec := httptest.NewRecorder()
	env.handler.Delete(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestAdminMappingsDelete_DeleteMappingError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockMappingsErrStore{DB: database, deleteMappingErr: fmt.Errorf("db failure")}
	h := newMappingsMockHandler(t, mock)

	req := httptest.NewRequest(http.MethodPost, "/admin/mappings/1/delete", nil)
	req = withChiURLParam(req, "id", "1")
	rec := httptest.NewRecorder()
	h.Delete(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "error page") {
		t.Errorf("expected error page, got: %s", rec.Body.String())
	}
}

func TestAdminMappingsDeleteAll_DeleteAllMappingsError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockMappingsErrStore{DB: database, deleteAllMappingsErr: fmt.Errorf("db failure")}
	h := newMappingsMockHandler(t, mock)

	form := url.Values{}
	form.Set("auth_provider_id", "local")
	form.Set("username", "testuser")
	req := httptest.NewRequest(http.MethodPost, "/admin/mappings/delete-all", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.DeleteAll(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "error page") {
		t.Errorf("expected error page, got: %s", rec.Body.String())
	}
}

// TestAdminMappingsSearch_ListIDPsError covers the path where ListIDPs fails in Search.
// The failure is non-fatal (just logged); the handler continues and renders 200.
func TestAdminMappingsSearch_ListIDPsError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockMappingsErrStore{DB: database, listIDPsErr: fmt.Errorf("db failure")}
	h := newMappingsMockHandler(t, mock)

	req := httptest.NewRequest(http.MethodGet, "/admin/mappings/search?username=testuser", nil)
	rec := httptest.NewRecorder()
	h.Search(rec, req)

	// ListIDPs failure is non-fatal (just logs); the handler still renders the results page.
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (ListIDPs error is non-fatal), got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminMappingsSearch_DirectoryLookupSuccess covers the path where the provider is
// found in the registry and SearchUser succeeds, populating directoryDN.
func TestAdminMappingsSearch_DirectoryLookupSuccess(t *testing.T) {
	env := setupMappingsTest(t)
	cookies := env.createAdminSession(t)

	// Register a mock provider that returns a real DN from SearchUser.
	env.handler.registry.Register("corp-ad", &mockProviderWithDN{
		mockProvider: mockProvider{id: "corp-ad"},
		searchUserDN: "CN=testuser,DC=example,DC=com",
	})

	rec := env.serveWithAdminSession(t, env.handler.Search, http.MethodGet,
		"/admin/mappings/search?username=testuser&auth_provider_id=corp-ad", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "mappings page") {
		t.Errorf("expected mappings page content, got: %s", rec.Body.String())
	}
}

// TestMappingsSearch_ProviderNotInRegistry covers lines 154-157 where the provider
// referenced by auth_provider_id is not registered in the IDP registry.
func TestMappingsSearch_ProviderNotInRegistry(t *testing.T) {
	env := setupMappingsTest(t)
	cookies := env.createAdminSession(t)

	// Search with a non-local, non-wildcard provider that is NOT in the registry.
	rec := env.serveWithAdminSession(t, env.handler.Search, http.MethodGet,
		"/admin/mappings/search?username=testuser&auth_provider_id=unregistered-idp", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "mappings page") {
		t.Errorf("expected mappings page content, got: %s", rec.Body.String())
	}
}

// TestMappingsSearch_DirectorySearchFails covers lines 160-164 where the first
// SearchUser call fails and the fallback sAMAccountName search is attempted.
func TestMappingsSearch_DirectorySearchFails(t *testing.T) {
	env := setupMappingsTest(t)
	cookies := env.createAdminSession(t)

	// Register a provider that returns an error from both SearchUser attempts.
	env.handler.registry.Register("corp-ad", &mockProviderSearchFail{})

	rec := env.serveWithAdminSession(t, env.handler.Search, http.MethodGet,
		"/admin/mappings/search?username=testuser&auth_provider_id=corp-ad", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "mappings page") {
		t.Errorf("expected mappings page content, got: %s", rec.Body.String())
	}
}

// TestDeleteAll_ParseFormError covers admin_mappings.go:238-241 where ParseForm
// fails (unreadable request body) → 400 Bad Request.
func TestDeleteAll_ParseFormError(t *testing.T) {
	env := setupMappingsTest(t)
	cookies := env.createAdminSession(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/mappings/delete-all", errReader{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	wrapped := env.sm.Middleware(http.HandlerFunc(env.handler.DeleteAll))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for ParseForm error, got %d; body: %s", rec.Code, rec.Body.String())
	}
}
