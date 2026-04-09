package handler

import (
	"context"
	"encoding/json"
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

type groupsTestEnv struct {
	db      *db.DB
	handler *AdminGroupsHandler
	sm      *auth.SessionManager
	audit   *audit.Logger
}

func stubGroupsRenderer(t *testing.T) *Renderer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	funcMap := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"pages":    func(n int) []int { return nil },
	}
	pages := make(map[string]*template.Template)
	pages["admin_groups.html"] = template.Must(template.New("admin_groups.html").Funcs(funcMap).Parse(`{{define "base"}}admin groups page{{end}}`))
	pages["error.html"] = template.Must(template.New("error.html").Funcs(funcMap).Parse(`{{define "base"}}error page{{end}}`))
	return &Renderer{pages: pages, logger: logger}
}

func setupGroupsTest(t *testing.T) *groupsTestEnv {
	t.Helper()

	database := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := stubGroupsRenderer(t)

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

	registry := idp.NewRegistry(logger)
	h := NewAdminGroupsHandler(database, registry, renderer, auditLog, logger)

	return &groupsTestEnv{
		db:      database,
		handler: h,
		sm:      sm,
		audit:   auditLog,
	}
}

func (env *groupsTestEnv) createAdminSession(t *testing.T) []*http.Cookie {
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

func (env *groupsTestEnv) serveWithAdminSession(t *testing.T, handler http.HandlerFunc, method, path string, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
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

func (env *groupsTestEnv) createTestIDP(t *testing.T) string {
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
	return record.ID
}

func TestGroupsList(t *testing.T) {
	env := setupGroupsTest(t)
	cookies := env.createAdminSession(t)

	rec := env.serveWithAdminSession(t, env.handler.List, http.MethodGet, "/admin/groups", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "admin groups page") {
		t.Errorf("expected admin groups content, got: %s", rec.Body.String())
	}
}

func TestGroupsCreate(t *testing.T) {
	env := setupGroupsTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDP(t)

	form := url.Values{}
	form.Set("idp_id", idpID)
	form.Set("group_dn", "cn=admins,ou=Groups,dc=example,dc=com")
	form.Set("description", "Admin group")

	rec := env.serveWithAdminSession(t, env.handler.Create, http.MethodPost, "/admin/groups", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/groups" {
		t.Errorf("expected redirect to /admin/groups, got %s", loc)
	}

	// Verify group was created.
	groups, err := env.db.ListAdminGroups(context.Background())
	if err != nil {
		t.Fatalf("listing admin groups: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].GroupDN != "cn=admins,ou=Groups,dc=example,dc=com" {
		t.Errorf("expected group DN cn=admins,..., got %q", groups[0].GroupDN)
	}
}

func TestGroupsCreateMissingFields(t *testing.T) {
	env := setupGroupsTest(t)
	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("description", "Missing required fields")

	rec := env.serveWithAdminSession(t, env.handler.Create, http.MethodPost, "/admin/groups", cookies, form.Encode())

	// Should re-render the form (200), not redirect.
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 (form re-render), got %d", rec.Code)
	}
}

func TestGroupsDelete(t *testing.T) {
	env := setupGroupsTest(t)
	cookies := env.createAdminSession(t)
	env.createTestIDP(t)

	// Create a group to delete.
	group := &db.AdminGroup{
		IDPID:       "test-idp",
		GroupDN:     "cn=admins,ou=Groups,dc=example,dc=com",
		Description: "Admin group",
	}
	if err := env.db.CreateAdminGroup(context.Background(), group); err != nil {
		t.Fatalf("creating admin group: %v", err)
	}

	// List to get the ID.
	groups, err := env.db.ListAdminGroups(context.Background())
	if err != nil {
		t.Fatalf("listing admin groups: %v", err)
	}
	if len(groups) == 0 {
		t.Fatal("expected at least one group")
	}
	groupID := groups[0].ID

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", fmt.Sprintf("%d", groupID))
		env.handler.Delete(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/groups/1/delete", cookies, "")

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify group was deleted.
	groups, err = env.db.ListAdminGroups(context.Background())
	if err != nil {
		t.Fatalf("listing admin groups: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("expected 0 groups after delete, got %d", len(groups))
	}
}

// --- Additional tests ---

// TestAdminGroupsMembers_ProviderNotFound verifies that Members returns a JSON
// error when the IDP provider is not registered in the registry.
func TestAdminGroupsMembers_ProviderNotFound(t *testing.T) {
	env := setupGroupsTest(t)
	idpID := env.createTestIDP(t)

	// Create an admin group whose IDP is NOT registered in the registry.
	group := &db.AdminGroup{
		IDPID:   idpID,
		GroupDN: "cn=admins,ou=Groups,dc=example,dc=com",
	}
	if err := env.db.CreateAdminGroup(context.Background(), group); err != nil {
		t.Fatalf("creating admin group: %v", err)
	}

	// Get the group ID.
	groups, err := env.db.ListAdminGroups(context.Background())
	if err != nil {
		t.Fatalf("listing admin groups: %v", err)
	}
	if len(groups) == 0 {
		t.Fatal("expected at least one admin group")
	}
	groupID := groups[0].ID

	// Call Members with no provider registered in the registry (setupGroupsTest
	// creates an empty registry).
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", fmt.Sprintf("%d", groupID))
		env.handler.Members(w, r)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/groups/1/members", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 (provider not available), got %d", rec.Code)
	}

	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON response: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected status 'error', got %q", result["status"])
	}
	if result["message"] != "Provider not available" {
		t.Errorf("expected message 'Provider not available', got %q", result["message"])
	}
}

// TestAdminGroupsMembers_GroupNotFound verifies Members returns 404 JSON when
// the group ID does not exist in the database.
func TestAdminGroupsMembers_GroupNotFound(t *testing.T) {
	env := setupGroupsTest(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "99999")
		env.handler.Members(w, r)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/groups/99999/members", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}

// TestSanitizeDN verifies that sanitizeDN replaces the full DN with a label.
func TestSanitizeDN(t *testing.T) {
	tests := []struct {
		errMsg string
		dn     string
		label  string
		want   string
	}{
		{
			errMsg: "failed for CN=jdoe,OU=Users,DC=example,DC=com: timeout",
			dn:     "CN=jdoe,OU=Users,DC=example,DC=com",
			label:  "jdoe",
			want:   "failed for jdoe: timeout",
		},
		{
			errMsg: "no error to sanitize",
			dn:     "",
			label:  "nobody",
			want:   "no error to sanitize",
		},
		{
			errMsg: "dn appears twice: CN=x,DC=y and CN=x,DC=y",
			dn:     "CN=x,DC=y",
			label:  "user",
			want:   "dn appears twice: user and user",
		},
		{
			errMsg: "no dn present",
			dn:     "CN=not,DC=here",
			label:  "someone",
			want:   "no dn present",
		},
	}

	for _, tc := range tests {
		got := sanitizeDN(tc.errMsg, tc.dn, tc.label)
		if got != tc.want {
			t.Errorf("sanitizeDN(%q, %q, %q) = %q, want %q",
				tc.errMsg, tc.dn, tc.label, got, tc.want)
		}
	}
}

// TestWriteJSON verifies that writeJSON writes valid JSON with the correct
// Content-Type and status code.
func TestWriteJSON(t *testing.T) {
	tests := []struct {
		status int
		data   any
	}{
		{http.StatusOK, map[string]string{"status": "success", "count": "3"}},
		{http.StatusNotFound, map[string]string{"status": "error", "message": "not found"}},
		{http.StatusBadRequest, map[string]any{"status": "error", "code": 400}},
	}

	for _, tc := range tests {
		rec := httptest.NewRecorder()
		writeJSON(rec, tc.status, tc.data)

		if rec.Code != tc.status {
			t.Errorf("writeJSON status: expected %d, got %d", tc.status, rec.Code)
		}
		ct := rec.Header().Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("writeJSON Content-Type: expected 'application/json', got %q", ct)
		}
		// Verify body is valid JSON.
		var decoded any
		if err := json.NewDecoder(rec.Body).Decode(&decoded); err != nil {
			t.Errorf("writeJSON produced invalid JSON: %v", err)
		}
	}
}

func TestGroupsDelete_InvalidID(t *testing.T) {
	env := setupGroupsTest(t)
	cookies := env.createAdminSession(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "not-a-number")
		env.handler.Delete(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/groups/not-a-number/delete", cookies, "")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for invalid ID, got %d", rec.Code)
	}
}

func TestGroupsMembers_InvalidID(t *testing.T) {
	env := setupGroupsTest(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "not-a-number")
		env.handler.Members(w, r)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/groups/not-a-number/members", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for invalid ID, got %d", rec.Code)
	}
}

func TestGroupsMembers_Success(t *testing.T) {
	env := setupGroupsTest(t)
	idpID := env.createTestIDP(t)

	// Register a mock provider that returns group members.
	env.handler.registry.Register(idpID, &mockProvider{
		id:           idpID,
		groupMembers: []string{"cn=user1,ou=Users,dc=example,dc=com", "cn=user2,ou=Users,dc=example,dc=com"},
	})

	group := &db.AdminGroup{
		IDPID:   idpID,
		GroupDN: "cn=admins,ou=Groups,dc=example,dc=com",
	}
	if err := env.db.CreateAdminGroup(context.Background(), group); err != nil {
		t.Fatalf("creating admin group: %v", err)
	}

	groups, err := env.db.ListAdminGroups(context.Background())
	if err != nil {
		t.Fatalf("listing admin groups: %v", err)
	}
	groupID := groups[0].ID

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", fmt.Sprintf("%d", groupID))
		env.handler.Members(w, r)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/groups/1/members", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON response: %v", err)
	}
	if result["status"] != "success" {
		t.Errorf("expected status 'success', got %q", result["status"])
	}
}

func TestGroupsMembers_ProviderError(t *testing.T) {
	env := setupGroupsTest(t)
	idpID := env.createTestIDP(t)

	// Register a mock provider that returns an error.
	env.handler.registry.Register(idpID, &mockProvider{
		id:         idpID,
		membersErr: fmt.Errorf("LDAP connection timeout"),
	})

	group := &db.AdminGroup{
		IDPID:   idpID,
		GroupDN: "cn=admins,ou=Groups,dc=example,dc=com",
	}
	if err := env.db.CreateAdminGroup(context.Background(), group); err != nil {
		t.Fatalf("creating admin group: %v", err)
	}

	groups, err := env.db.ListAdminGroups(context.Background())
	if err != nil {
		t.Fatalf("listing admin groups: %v", err)
	}
	groupID := groups[0].ID

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", fmt.Sprintf("%d", groupID))
		env.handler.Members(w, r)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/groups/1/members", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// --- DB error path tests ---

type mockGroupsErrStore struct {
	*db.DB
	listAdminGroupsErr  error
	listIDPsErr         error
	createAdminGroupErr error
	deleteAdminGroupErr error
}

func (m *mockGroupsErrStore) ListAdminGroups(ctx context.Context) ([]db.AdminGroup, error) {
	if m.listAdminGroupsErr != nil {
		return nil, m.listAdminGroupsErr
	}
	return m.DB.ListAdminGroups(ctx)
}

func (m *mockGroupsErrStore) ListIDPs(ctx context.Context) ([]db.IdentityProviderRecord, error) {
	if m.listIDPsErr != nil {
		return nil, m.listIDPsErr
	}
	return m.DB.ListIDPs(ctx)
}

func (m *mockGroupsErrStore) CreateAdminGroup(ctx context.Context, g *db.AdminGroup) error {
	if m.createAdminGroupErr != nil {
		return m.createAdminGroupErr
	}
	return m.DB.CreateAdminGroup(ctx, g)
}

func (m *mockGroupsErrStore) DeleteAdminGroup(ctx context.Context, id int64) error {
	if m.deleteAdminGroupErr != nil {
		return m.deleteAdminGroupErr
	}
	return m.DB.DeleteAdminGroup(ctx, id)
}

func newGroupsMockHandler(t *testing.T, database *db.DB, mock *mockGroupsErrStore) *AdminGroupsHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	renderer := stubGroupsRenderer(t)

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

	registry := idp.NewRegistry(logger)
	return NewAdminGroupsHandler(mock, registry, renderer, auditLog, logger)
}

// TestAdminGroupsList_ListAdminGroupsError covers the List error path when
// ListAdminGroups fails → 500.
func TestAdminGroupsList_ListAdminGroupsError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockGroupsErrStore{DB: database, listAdminGroupsErr: fmt.Errorf("db failure")}
	h := newGroupsMockHandler(t, database, mock)

	req := httptest.NewRequest(http.MethodGet, "/admin/groups", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when ListAdminGroups fails, got %d", rec.Code)
	}
}

// TestAdminGroupsList_ListIDPsError covers the List error path when ListIDPs
// fails (after ListAdminGroups succeeds) → 500.
func TestAdminGroupsList_ListIDPsError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockGroupsErrStore{DB: database, listIDPsErr: fmt.Errorf("db failure")}
	h := newGroupsMockHandler(t, database, mock)

	req := httptest.NewRequest(http.MethodGet, "/admin/groups", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when ListIDPs fails, got %d", rec.Code)
	}
}

// TestAdminGroupsCreate_DBError covers Create when CreateAdminGroup fails →
// re-renders the form with an error flash (200).
func TestAdminGroupsCreate_DBError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockGroupsErrStore{DB: database, createAdminGroupErr: fmt.Errorf("db failure")}
	h := newGroupsMockHandler(t, database, mock)

	form := url.Values{}
	form.Set("idp_id", "corp-ad")
	form.Set("group_dn", "cn=admins,ou=Groups,dc=example,dc=com")
	req := httptest.NewRequest(http.MethodPost, "/admin/groups", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Create(rec, req)

	// CreateAdminGroup failure re-renders the form (200).
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (form re-render) when CreateAdminGroup fails, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "admin groups page") {
		t.Errorf("expected admin groups page, got: %s", rec.Body.String())
	}
}

// TestAdminGroupsDelete_DBError covers Delete when DeleteAdminGroup fails → 500.
func TestAdminGroupsDelete_DBError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockGroupsErrStore{DB: database, deleteAdminGroupErr: fmt.Errorf("db failure")}
	h := newGroupsMockHandler(t, database, mock)

	req := withChiURLParam(
		httptest.NewRequest(http.MethodPost, "/admin/groups/1/delete", nil),
		"id", "1",
	)
	rec := httptest.NewRecorder()
	h.Delete(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when DeleteAdminGroup fails, got %d", rec.Code)
	}
}

// TestAdminGroupsMembers_ListGroupsError covers the Members path when
// ListAdminGroups fails → 500 JSON response.
func TestAdminGroupsMembers_ListGroupsError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockGroupsErrStore{DB: database, listAdminGroupsErr: fmt.Errorf("db failure")}
	h := newGroupsMockHandler(t, database, mock)

	req := withChiURLParam(
		httptest.NewRequest(http.MethodGet, "/admin/groups/1/members", nil),
		"id", "1",
	)
	rec := httptest.NewRecorder()
	h.Members(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when ListAdminGroups fails in Members, got %d", rec.Code)
	}

	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected error status, got %s", result["status"])
	}
}

// TestAdminGroupsCreate_ParseFormError covers Create when ParseForm fails → 400.
func TestAdminGroupsCreate_ParseFormError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockGroupsErrStore{DB: database}
	h := newGroupsMockHandler(t, database, mock)

	req := httptest.NewRequest(http.MethodPost, "/admin/groups", errReader{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Create(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when ParseForm fails, got %d", rec.Code)
	}
}
