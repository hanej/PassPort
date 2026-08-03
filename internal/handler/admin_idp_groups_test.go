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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/db"
)

type idpGroupTestEnv struct {
	db      *db.DB
	handler *AdminIDPGroupHandler
	sm      *auth.SessionManager
}

func setupIDPGroupTest(t *testing.T) *idpGroupTestEnv {
	t.Helper()

	database := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	pages := map[string]*template.Template{
		"admin_idp_groups.html": template.Must(template.New("admin_idp_groups.html").Parse(`{{define "base"}}provider groups page{{end}}`)),
		"error.html":            template.Must(template.New("error.html").Parse(`{{define "base"}}error page{{end}}`)),
	}
	renderer := &Renderer{pages: pages, logger: logger}

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

	return &idpGroupTestEnv{
		db:      database,
		handler: NewAdminIDPGroupHandler(database, renderer, auditLog, logger),
		sm:      auth.NewSessionManager(database, 30*time.Minute, false, logger),
	}
}

func (env *idpGroupTestEnv) adminSession(t *testing.T) []*http.Cookie {
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
	if _, err := env.sm.CreateSession(rec, req, "local", "", "admin", true, false); err != nil {
		t.Fatalf("creating session: %v", err)
	}
	return rec.Result().Cookies()
}

func (env *idpGroupTestEnv) serveForm(t *testing.T, h http.HandlerFunc, method, path string, cookies []*http.Cookie, form url.Values) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	env.sm.Middleware(h).ServeHTTP(rec, req)
	return rec
}

func (env *idpGroupTestEnv) serveJSON(t *testing.T, h http.HandlerFunc, path string, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	env.sm.Middleware(h).ServeHTTP(rec, req)
	return rec
}

func (env *idpGroupTestEnv) createIDP(t *testing.T, id string) {
	t.Helper()
	err := env.db.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           id,
		FriendlyName: id,
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   "{}",
	})
	if err != nil {
		t.Fatalf("creating idp %q: %v", id, err)
	}
}

func (env *idpGroupTestEnv) createGroup(t *testing.T, name string) int64 {
	t.Helper()
	g := &db.IDPGroup{Name: name}
	if err := env.db.CreateIDPGroup(context.Background(), g); err != nil {
		t.Fatalf("creating group %q: %v", name, err)
	}
	return g.ID
}

func TestAdminIDPGroups_Show(t *testing.T) {
	env := setupIDPGroupTest(t)
	cookies := env.adminSession(t)
	env.createIDP(t, "corp-ad")
	env.createGroup(t, "Corporate")

	rec := env.serveForm(t, env.handler.Show, http.MethodGet, "/admin/idp/groups", cookies, url.Values{})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestAdminIDPGroups_Create(t *testing.T) {
	env := setupIDPGroupTest(t)
	cookies := env.adminSession(t)

	form := url.Values{}
	form.Set("name", "  Corporate  ")
	form.Set("description", " HQ directories ")
	form.Set("icon", "bi-building")
	form.Set("collapsible", "1")
	form.Set("start_collapsed", "1")

	rec := env.serveForm(t, env.handler.Create, http.MethodPost, "/admin/idp/groups", cookies, form)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}

	groups, err := env.db.ListIDPGroups(context.Background())
	if err != nil {
		t.Fatalf("listing groups: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].Name != "Corporate" || groups[0].Description != "HQ directories" {
		t.Errorf("expected fields to be trimmed, got %+v", groups[0])
	}
	if groups[0].Icon != "bi-building" || !groups[0].Collapsible {
		t.Errorf("unexpected icon/collapsible: %+v", groups[0])
	}
	if !groups[0].StartCollapsed {
		t.Errorf("expected group to start collapsed: %+v", groups[0])
	}
}

func TestAdminIDPGroups_CreateRejectsBadName(t *testing.T) {
	env := setupIDPGroupTest(t)
	cookies := env.adminSession(t)

	for _, name := range []string{"", "   ", strings.Repeat("x", maxGroupNameLen+1)} {
		form := url.Values{}
		form.Set("name", name)

		rec := env.serveForm(t, env.handler.Create, http.MethodPost, "/admin/idp/groups", cookies, form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("name %q: expected 400, got %d", name, rec.Code)
		}
	}

	groups, err := env.db.ListIDPGroups(context.Background())
	if err != nil {
		t.Fatalf("listing groups: %v", err)
	}
	if len(groups) != 0 {
		t.Fatalf("expected no groups to be created, got %d", len(groups))
	}
}

func TestAdminIDPGroups_Update(t *testing.T) {
	env := setupIDPGroupTest(t)
	cookies := env.adminSession(t)
	id := env.createGroup(t, "Corporate")

	form := url.Values{}
	form.Set("name", "Renamed")
	form.Set("icon", "bi-people")

	req := httptest.NewRequest(http.MethodPost, "/admin/idp/groups/1", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	req = withChiURLParam(req, "id", "1")
	rec := httptest.NewRecorder()
	env.sm.Middleware(http.HandlerFunc(env.handler.Update)).ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}

	got, err := env.db.GetIDPGroup(context.Background(), id)
	if err != nil {
		t.Fatalf("getting group: %v", err)
	}
	if got.Name != "Renamed" || got.Icon != "bi-people" {
		t.Errorf("unexpected group after update: %+v", got)
	}
}

func TestAdminIDPGroups_UpdateNotFound(t *testing.T) {
	env := setupIDPGroupTest(t)
	cookies := env.adminSession(t)

	form := url.Values{}
	form.Set("name", "Ghost")

	req := httptest.NewRequest(http.MethodPost, "/admin/idp/groups/999", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	req = withChiURLParam(req, "id", "999")
	rec := httptest.NewRecorder()
	env.sm.Middleware(http.HandlerFunc(env.handler.Update)).ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestAdminIDPGroups_Delete(t *testing.T) {
	env := setupIDPGroupTest(t)
	cookies := env.adminSession(t)
	id := env.createGroup(t, "Corporate")
	env.createIDP(t, "corp-ad")

	err := env.db.SetIDPArrangement(context.Background(), []int64{id}, []db.IDPPlacement{
		{IDPID: "corp-ad", GroupID: &id, DisplayOrder: 0},
	})
	if err != nil {
		t.Fatalf("arranging: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/idp/groups/1/delete", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	req = withChiURLParam(req, "id", "1")
	rec := httptest.NewRecorder()
	env.sm.Middleware(http.HandlerFunc(env.handler.Delete)).ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}

	if _, err := env.db.GetIDP(context.Background(), "corp-ad"); err != nil {
		t.Fatalf("provider should survive group deletion: %v", err)
	}
}

func TestAdminIDPGroups_DeleteInvalidID(t *testing.T) {
	env := setupIDPGroupTest(t)
	cookies := env.adminSession(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/idp/groups/abc/delete", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	req = withChiURLParam(req, "id", "abc")
	rec := httptest.NewRecorder()
	env.sm.Middleware(http.HandlerFunc(env.handler.Delete)).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestAdminIDPGroups_Arrange(t *testing.T) {
	env := setupIDPGroupTest(t)
	cookies := env.adminSession(t)
	corp := env.createGroup(t, "Corporate")
	partners := env.createGroup(t, "Partners")
	for _, id := range []string{"a", "b", "c", "d"} {
		env.createIDP(t, id)
	}

	// Positions inside Corporate are deliberately reverse-alphabetical, so the
	// stored order cannot be mistaken for the default friendly_name sort.
	body := `{"group_order":[` + itoa(partners) + `,` + itoa(corp) + `],"sections":[` +
		`{"group_id":` + itoa(partners) + `,"idp_ids":["b"]},` +
		`{"group_id":` + itoa(corp) + `,"idp_ids":["d","a"]},` +
		`{"group_id":null,"idp_ids":["c"]}]}`

	rec := env.serveJSON(t, env.handler.Arrange, "/admin/idp/groups/arrange", cookies, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	groups, err := env.db.ListIDPGroups(context.Background())
	if err != nil {
		t.Fatalf("listing groups: %v", err)
	}
	gotGroups := []int64{}
	for _, g := range groups {
		gotGroups = append(gotGroups, g.ID)
	}
	if len(gotGroups) != 2 || gotGroups[0] != partners || gotGroups[1] != corp {
		t.Errorf("expected group order [%d %d], got %v", partners, corp, gotGroups)
	}

	idps, err := env.db.ListIDPs(context.Background())
	if err != nil {
		t.Fatalf("listing providers: %v", err)
	}
	byID := make(map[string]db.IdentityProviderRecord, len(idps))
	for _, rec := range idps {
		byID[rec.ID] = rec
	}

	// Position within the group must round-trip, not collapse to zero.
	if byID["d"].DisplayOrder != 0 || byID["a"].DisplayOrder != 1 {
		t.Errorf("expected d=0 and a=1 inside Corporate, got d=%d a=%d",
			byID["d"].DisplayOrder, byID["a"].DisplayOrder)
	}
	if byID["d"].GroupID == nil || *byID["d"].GroupID != corp {
		t.Errorf("expected provider d in Corporate, got %v", byID["d"].GroupID)
	}

	// ListIDPs orders by display_order, so d must come back before a.
	var corpOrder []string
	for _, rec := range idps {
		if rec.GroupID != nil && *rec.GroupID == corp {
			corpOrder = append(corpOrder, rec.ID)
		}
	}
	if len(corpOrder) != 2 || corpOrder[0] != "d" || corpOrder[1] != "a" {
		t.Errorf("expected Corporate providers in order [d a], got %v", corpOrder)
	}

	if byID["c"].GroupID != nil {
		t.Errorf("expected provider c to be ungrouped, got %d", *byID["c"].GroupID)
	}
}

// Local Admin has no identity_providers row, so the handler has to accept its
// reserved ID as a valid arrangement target and route it to its own storage.
func TestAdminIDPGroups_ArrangePlacesLocalAdmin(t *testing.T) {
	env := setupIDPGroupTest(t)
	cookies := env.adminSession(t)
	corp := env.createGroup(t, "Corporate")
	env.createIDP(t, "a")

	body := `{"group_order":[` + itoa(corp) + `],"sections":[` +
		`{"group_id":` + itoa(corp) + `,"idp_ids":["a","local"]}]}`

	rec := env.serveJSON(t, env.handler.Arrange, "/admin/idp/groups/arrange", cookies, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	p, err := env.db.GetLocalAdminPlacement(context.Background())
	if err != nil {
		t.Fatalf("getting placement: %v", err)
	}
	if p.GroupID == nil || *p.GroupID != corp {
		t.Fatalf("expected local admin in Corporate, got %v", p.GroupID)
	}
	if p.DisplayOrder != 1 {
		t.Errorf("expected local admin at position 1, got %d", p.DisplayOrder)
	}
}

func TestAdminIDPGroups_ArrangeRejectsBadPayloads(t *testing.T) {
	env := setupIDPGroupTest(t)
	cookies := env.adminSession(t)
	corp := env.createGroup(t, "Corporate")
	env.createIDP(t, "a")

	tests := []struct {
		name string
		body string
	}{
		{"malformed JSON", `{`},
		{"unknown field", `{"group_order":[],"sections":[],"surprise":1}`},
		{"unknown group in order", `{"group_order":[4242],"sections":[]}`},
		{"unknown group in section", `{"group_order":[],"sections":[{"group_id":4242,"idp_ids":[]}]}`},
		{"unknown provider", `{"group_order":[],"sections":[{"group_id":null,"idp_ids":["ghost"]}]}`},
		{"duplicate provider", `{"group_order":[` + itoa(corp) + `],"sections":[` +
			`{"group_id":` + itoa(corp) + `,"idp_ids":["a"]},{"group_id":null,"idp_ids":["a"]}]}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := env.serveJSON(t, env.handler.Arrange, "/admin/idp/groups/arrange", cookies, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
			var payload map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
				t.Fatalf("expected a JSON error body, got %q", rec.Body.String())
			}
			if payload["error"] == "" {
				t.Errorf("expected an error message, got %q", rec.Body.String())
			}
		})
	}

	// Nothing may have been persisted by any of the rejected payloads.
	got, err := env.db.GetIDP(context.Background(), "a")
	if err != nil {
		t.Fatalf("getting provider: %v", err)
	}
	if got.GroupID != nil {
		t.Errorf("expected provider to remain ungrouped, got group %d", *got.GroupID)
	}
}

func TestAdminIDPGroups_CreateRejectsDuplicateName(t *testing.T) {
	env := setupIDPGroupTest(t)
	cookies := env.adminSession(t)
	env.createGroup(t, "Corporate")

	form := url.Values{}
	form.Set("name", "  corporate ")

	rec := env.serveForm(t, env.handler.Create, http.MethodPost, "/admin/idp/groups", cookies, form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}

	groups, err := env.db.ListIDPGroups(context.Background())
	if err != nil {
		t.Fatalf("listing groups: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("expected the duplicate to be rejected, got %d groups", len(groups))
	}
}

func TestAdminIDPGroups_UpdateNameConflicts(t *testing.T) {
	env := setupIDPGroupTest(t)
	cookies := env.adminSession(t)
	corp := env.createGroup(t, "Corporate")
	env.createGroup(t, "Partners")

	update := func(id int64, name string) int {
		t.Helper()
		form := url.Values{}
		form.Set("name", name)
		req := httptest.NewRequest(http.MethodPost, "/admin/idp/groups/"+itoa(id), strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		req = withChiURLParam(req, "id", itoa(id))
		rec := httptest.NewRecorder()
		env.sm.Middleware(http.HandlerFunc(env.handler.Update)).ServeHTTP(rec, req)
		return rec.Code
	}

	if code := update(corp, "PARTNERS"); code != http.StatusBadRequest {
		t.Errorf("renaming onto another group: expected 400, got %d", code)
	}
	// Keeping its own name must still be allowed, so other fields can be edited.
	if code := update(corp, "Corporate"); code != http.StatusFound {
		t.Errorf("keeping its own name: expected 302, got %d", code)
	}
}

func TestNormalizeGroupIcon(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"bi-building", "bi-building"},
		{"  bi-people-fill  ", "bi-people-fill"},
		{"bi-1-circle", "bi-1-circle"},
		{"", ""},
		{"building", ""},
		{"bi-Building", ""},
		{`bi-x" onload="alert(1)`, ""},
		{"bi-x y", ""},
		{"bi-x/../y", ""},
	}

	for _, tc := range tests {
		if got := normalizeGroupIcon(tc.in); got != tc.want {
			t.Errorf("normalizeGroupIcon(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func itoa(v int64) string {
	return strconv.FormatInt(v, 10)
}

// --- DB error path tests ---

type mockIDPGroupErrStore struct {
	*db.DB
	listGroupsErr  error
	listIDPsErr    error
	createGroupErr error
	updateGroupErr error
	deleteGroupErr error
	setArrangeErr  error
}

func (m *mockIDPGroupErrStore) ListIDPGroups(ctx context.Context) ([]db.IDPGroup, error) {
	if m.listGroupsErr != nil {
		return nil, m.listGroupsErr
	}
	return m.DB.ListIDPGroups(ctx)
}

func (m *mockIDPGroupErrStore) ListIDPs(ctx context.Context) ([]db.IdentityProviderRecord, error) {
	if m.listIDPsErr != nil {
		return nil, m.listIDPsErr
	}
	return m.DB.ListIDPs(ctx)
}

func (m *mockIDPGroupErrStore) CreateIDPGroup(ctx context.Context, g *db.IDPGroup) error {
	if m.createGroupErr != nil {
		return m.createGroupErr
	}
	return m.DB.CreateIDPGroup(ctx, g)
}

func (m *mockIDPGroupErrStore) UpdateIDPGroup(ctx context.Context, g *db.IDPGroup) error {
	if m.updateGroupErr != nil {
		return m.updateGroupErr
	}
	return m.DB.UpdateIDPGroup(ctx, g)
}

func (m *mockIDPGroupErrStore) DeleteIDPGroup(ctx context.Context, id int64) error {
	if m.deleteGroupErr != nil {
		return m.deleteGroupErr
	}
	return m.DB.DeleteIDPGroup(ctx, id)
}

func (m *mockIDPGroupErrStore) SetIDPArrangement(ctx context.Context, groupOrder []int64, placements []db.IDPPlacement) error {
	if m.setArrangeErr != nil {
		return m.setArrangeErr
	}
	return m.DB.SetIDPArrangement(ctx, groupOrder, placements)
}

// withStore swaps in a failing store while keeping the rest of the wiring.
func (env *idpGroupTestEnv) withStore(store db.Store) *AdminIDPGroupHandler {
	h := *env.handler
	h.store = store
	return &h
}

func (env *idpGroupTestEnv) formRequest(t *testing.T, method, path string, cookies []*http.Cookie, form url.Values) *http.Request {
	t.Helper()

	req := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

func (env *idpGroupTestEnv) serve(t *testing.T, h http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	env.sm.Middleware(h).ServeHTTP(rec, req)
	return rec
}

func TestAdminIDPGroups_StoreErrors(t *testing.T) {
	boom := errors.New("boom")

	tests := []struct {
		name   string
		mock   *mockIDPGroupErrStore
		call   func(env *idpGroupTestEnv, h *AdminIDPGroupHandler, cookies []*http.Cookie) *httptest.ResponseRecorder
		want   int
		wantIn string
	}{
		{
			name: "show list groups fails",
			mock: &mockIDPGroupErrStore{listGroupsErr: boom},
			call: func(env *idpGroupTestEnv, h *AdminIDPGroupHandler, c []*http.Cookie) *httptest.ResponseRecorder {
				return env.serveForm(t, h.Show, http.MethodGet, "/admin/idp/groups", c, nil)
			},
			want: http.StatusInternalServerError,
		},
		{
			name: "show list providers fails",
			mock: &mockIDPGroupErrStore{listIDPsErr: boom},
			call: func(env *idpGroupTestEnv, h *AdminIDPGroupHandler, c []*http.Cookie) *httptest.ResponseRecorder {
				return env.serveForm(t, h.Show, http.MethodGet, "/admin/idp/groups", c, nil)
			},
			want: http.StatusInternalServerError,
		},
		{
			name: "create duplicate check fails",
			mock: &mockIDPGroupErrStore{listGroupsErr: boom},
			call: func(env *idpGroupTestEnv, h *AdminIDPGroupHandler, c []*http.Cookie) *httptest.ResponseRecorder {
				return env.serveForm(t, h.Create, http.MethodPost, "/admin/idp/groups", c, url.Values{"name": {"Corporate"}})
			},
			want: http.StatusInternalServerError,
		},
		{
			name: "create insert fails",
			mock: &mockIDPGroupErrStore{createGroupErr: boom},
			call: func(env *idpGroupTestEnv, h *AdminIDPGroupHandler, c []*http.Cookie) *httptest.ResponseRecorder {
				return env.serveForm(t, h.Create, http.MethodPost, "/admin/idp/groups", c, url.Values{"name": {"Corporate"}})
			},
			want: http.StatusInternalServerError,
		},
		{
			name: "update duplicate check fails",
			mock: &mockIDPGroupErrStore{listGroupsErr: boom},
			call: func(env *idpGroupTestEnv, h *AdminIDPGroupHandler, c []*http.Cookie) *httptest.ResponseRecorder {
				req := env.formRequest(t, http.MethodPost, "/admin/idp/groups/1", c, url.Values{"name": {"Corporate"}})
				return env.serve(t, h.Update, withChiURLParam(req, "id", "1"))
			},
			want: http.StatusInternalServerError,
		},
		{
			name: "update write fails",
			mock: &mockIDPGroupErrStore{updateGroupErr: boom},
			call: func(env *idpGroupTestEnv, h *AdminIDPGroupHandler, c []*http.Cookie) *httptest.ResponseRecorder {
				req := env.formRequest(t, http.MethodPost, "/admin/idp/groups/1", c, url.Values{"name": {"Corporate"}})
				return env.serve(t, h.Update, withChiURLParam(req, "id", "1"))
			},
			want: http.StatusInternalServerError,
		},
		{
			name: "delete missing group",
			mock: &mockIDPGroupErrStore{deleteGroupErr: db.ErrNotFound},
			call: func(env *idpGroupTestEnv, h *AdminIDPGroupHandler, c []*http.Cookie) *httptest.ResponseRecorder {
				req := env.formRequest(t, http.MethodPost, "/admin/idp/groups/9/delete", c, nil)
				return env.serve(t, h.Delete, withChiURLParam(req, "id", "9"))
			},
			want: http.StatusNotFound,
		},
		{
			name: "delete write fails",
			mock: &mockIDPGroupErrStore{deleteGroupErr: boom},
			call: func(env *idpGroupTestEnv, h *AdminIDPGroupHandler, c []*http.Cookie) *httptest.ResponseRecorder {
				req := env.formRequest(t, http.MethodPost, "/admin/idp/groups/1/delete", c, nil)
				return env.serve(t, h.Delete, withChiURLParam(req, "id", "1"))
			},
			want: http.StatusInternalServerError,
		},
		{
			name: "arrange list groups fails",
			mock: &mockIDPGroupErrStore{listGroupsErr: boom},
			call: func(env *idpGroupTestEnv, h *AdminIDPGroupHandler, c []*http.Cookie) *httptest.ResponseRecorder {
				return env.serveJSON(t, h.Arrange, "/admin/idp/groups/arrange", c, `{"group_order":[],"sections":[]}`)
			},
			want:   http.StatusInternalServerError,
			wantIn: "Failed to load provider groups",
		},
		{
			name: "arrange list providers fails",
			mock: &mockIDPGroupErrStore{listIDPsErr: boom},
			call: func(env *idpGroupTestEnv, h *AdminIDPGroupHandler, c []*http.Cookie) *httptest.ResponseRecorder {
				return env.serveJSON(t, h.Arrange, "/admin/idp/groups/arrange", c, `{"group_order":[],"sections":[]}`)
			},
			want:   http.StatusInternalServerError,
			wantIn: "Failed to load identity providers",
		},
		{
			name: "arrange write fails",
			mock: &mockIDPGroupErrStore{setArrangeErr: boom},
			call: func(env *idpGroupTestEnv, h *AdminIDPGroupHandler, c []*http.Cookie) *httptest.ResponseRecorder {
				return env.serveJSON(t, h.Arrange, "/admin/idp/groups/arrange", c, `{"group_order":[],"sections":[]}`)
			},
			want:   http.StatusInternalServerError,
			wantIn: "Failed to save arrangement",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := setupIDPGroupTest(t)
			cookies := env.adminSession(t)
			tc.mock.DB = env.db

			rec := tc.call(env, env.withStore(tc.mock), cookies)
			if rec.Code != tc.want {
				t.Fatalf("expected %d, got %d (body: %s)", tc.want, rec.Code, excerpt(rec.Body.String()))
			}
			if tc.wantIn != "" && !strings.Contains(rec.Body.String(), tc.wantIn) {
				t.Errorf("expected body to contain %q, got %s", tc.wantIn, excerpt(rec.Body.String()))
			}
		})
	}
}
