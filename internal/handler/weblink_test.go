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

	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
)

// weblinkForm builds an encoded create/update form for a weblink provider,
// deliberately including the directory-only fields that must be ignored.
func weblinkForm(id, name, targetURL string) string {
	v := url.Values{}
	v.Set("id", id)
	v.Set("friendly_name", name)
	v.Set("description", "External portal")
	v.Set("provider_type", "weblink")
	v.Set("weblink_url", targetURL)
	v.Set("mfa_provider_id", "mfa-1")
	v.Set("canonical_name[]", "email")
	v.Set("directory_attr[]", "mail")
	v.Set("source_canonical_attr", "email")
	v.Set("match_mode", "exact")
	return v.Encode()
}

func (env *idpTestEnv) createWebLinkIDP(t *testing.T, id, name, targetURL string) {
	t.Helper()
	cfg := idp.Config{URL: targetURL}
	configJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshaling config: %v", err)
	}
	rec := &db.IdentityProviderRecord{
		ID:           id,
		FriendlyName: name,
		ProviderType: string(idp.ProviderTypeWebLink),
		Enabled:      true,
		ConfigJSON:   string(configJSON),
	}
	if err := env.db.CreateIDP(context.Background(), rec); err != nil {
		t.Fatalf("creating weblink IDP: %v", err)
	}
}

func TestCreateWebLinkIDP_SkipsDirectoryFeatures(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	body := weblinkForm("portal", "Company Portal", "https://portal.example.com/sso")
	rec := env.serveWithAdminSession(t, env.handler.Create, http.MethodPost, "/admin/idp", cookies, body)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}

	ctx := context.Background()
	record, err := env.db.GetIDP(ctx, "portal")
	if err != nil {
		t.Fatalf("loading created IDP: %v", err)
	}
	if record.ProviderType != "weblink" {
		t.Errorf("expected provider_type weblink, got %q", record.ProviderType)
	}
	if record.MFAProviderID != nil {
		t.Errorf("MFA provider should be ignored for weblinks, got %q", *record.MFAProviderID)
	}

	var cfg idp.Config
	if err := json.Unmarshal([]byte(record.ConfigJSON), &cfg); err != nil {
		t.Fatalf("parsing config: %v", err)
	}
	if cfg.URL != "https://portal.example.com/sso" {
		t.Errorf("expected URL to be persisted, got %q", cfg.URL)
	}

	mappings, err := env.db.ListAttributeMappings(ctx, "portal")
	if err != nil {
		t.Fatalf("listing mappings: %v", err)
	}
	if len(mappings) != 0 {
		t.Errorf("attribute mappings should not be saved for weblinks, got %d", len(mappings))
	}

	rule, err := env.db.GetCorrelationRule(ctx, "portal")
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("loading correlation rule: %v", err)
	}
	if rule != nil {
		t.Error("correlation rule should not be saved for weblinks")
	}

	if _, ok := env.registry.Get("portal"); ok {
		t.Error("weblink providers must not be registered in the provider registry")
	}
}

// TestCreateWebLinkIDP_RejectsUnsafeURL verifies the scheme filter is applied on
// the write path, not only at render time.
func TestCreateWebLinkIDP_RejectsUnsafeURL(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	body := weblinkForm("evil", "Evil", "javascript:alert(document.cookie)")
	rec := env.serveWithAdminSession(t, env.handler.Create, http.MethodPost, "/admin/idp", cookies, body)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}

	record, err := env.db.GetIDP(context.Background(), "evil")
	if err != nil {
		t.Fatalf("loading created IDP: %v", err)
	}
	var cfg idp.Config
	if err := json.Unmarshal([]byte(record.ConfigJSON), &cfg); err != nil {
		t.Fatalf("parsing config: %v", err)
	}
	if cfg.URL != "" {
		t.Errorf("javascript: URL should not be persisted, got %q", cfg.URL)
	}
}

// TestCreateIDP_RejectsInvalidSlug guards the server-side slug check. The form's
// pattern attribute cannot be relied on: it is an invalid regex under the `v`
// flag browsers now apply, and it is trivially bypassed by a direct POST.
func TestCreateIDP_RejectsInvalidSlug(t *testing.T) {
	invalid := []string{
		"../../etc/passwd",
		"Corp-AD",
		"corp ad",
		"corp_ad",
		"corp/ad",
		"corp.ad",
		"corp%2fad",
	}

	for _, id := range invalid {
		t.Run(id, func(t *testing.T) {
			env := setupIDPTest(t)
			cookies := env.createAdminSession(t)

			body := weblinkForm(id, "Bad Slug", "https://example.com")
			rec := env.serveWithAdminSession(t, env.handler.Create, http.MethodPost, "/admin/idp", cookies, body)

			if rec.Code != http.StatusOK {
				t.Fatalf("expected the form to be re-rendered with 200, got %d", rec.Code)
			}
			if _, err := env.db.GetIDP(context.Background(), id); !errors.Is(err, db.ErrNotFound) {
				t.Errorf("provider with invalid slug %q should not have been created (err=%v)", id, err)
			}
		})
	}
}

func TestCreateIDP_AcceptsValidSlug(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	body := weblinkForm("corp-ad-2", "Fine", "https://example.com")
	rec := env.serveWithAdminSession(t, env.handler.Create, http.MethodPost, "/admin/idp", cookies, body)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if _, err := env.db.GetIDP(context.Background(), "corp-ad-2"); err != nil {
		t.Fatalf("expected provider to be created: %v", err)
	}
}

func TestUpdateWebLinkIDP_ClearsDirectoryFeatures(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)
	env.createWebLinkIDP(t, "portal", "Company Portal", "https://portal.example.com")

	ctx := context.Background()
	if err := env.db.SetAttributeMappings(ctx, "portal", []db.AttributeMapping{
		{IDPID: "portal", CanonicalName: "email", DirectoryAttr: "mail"},
	}); err != nil {
		t.Fatalf("seeding mappings: %v", err)
	}

	body := weblinkForm("portal", "Renamed Portal", "https://portal.example.com/new")
	req := httptest.NewRequest(http.MethodPost, "/admin/idp/portal", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	req = withChiURLParam(req, "id", "portal")

	rec := httptest.NewRecorder()
	env.sm.Middleware(http.HandlerFunc(env.handler.Update)).ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}

	mappings, err := env.db.ListAttributeMappings(ctx, "portal")
	if err != nil {
		t.Fatalf("listing mappings: %v", err)
	}
	if len(mappings) != 0 {
		t.Errorf("expected stale mappings to be cleared, got %d", len(mappings))
	}

	record, err := env.db.GetIDP(ctx, "portal")
	if err != nil {
		t.Fatalf("loading IDP: %v", err)
	}
	if record.MFAProviderID != nil {
		t.Errorf("MFA provider should be ignored for weblinks, got %q", *record.MFAProviderID)
	}
	var cfg idp.Config
	if err := json.Unmarshal([]byte(record.ConfigJSON), &cfg); err != nil {
		t.Fatalf("parsing config: %v", err)
	}
	if cfg.URL != "https://portal.example.com/new" {
		t.Errorf("expected updated URL, got %q", cfg.URL)
	}
}

func TestTestConnectionWebLink_ReturnsURL(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)
	env.createWebLinkIDP(t, "portal", "Company Portal", "https://portal.example.com/sso")

	req := httptest.NewRequest(http.MethodPost, "/admin/idp/portal/test", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	req = withChiURLParam(req, "id", "portal")

	rec := httptest.NewRecorder()
	env.sm.Middleware(http.HandlerFunc(env.handler.TestConnection)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp["status"] != "success" {
		t.Errorf("expected success, got %q (%s)", resp["status"], resp["message"])
	}
	if resp["url"] != "https://portal.example.com/sso" {
		t.Errorf("expected url in response, got %q", resp["url"])
	}
}

func TestTestConnectionWebLink_NoURL(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)
	env.createWebLinkIDP(t, "portal", "Company Portal", "")

	req := httptest.NewRequest(http.MethodPost, "/admin/idp/portal/test", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	req = withChiURLParam(req, "id", "portal")

	rec := httptest.NewRecorder()
	env.sm.Middleware(http.HandlerFunc(env.handler.TestConnection)).ServeHTTP(rec, req)

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if resp["status"] != "error" {
		t.Errorf("expected error status for weblink with no URL, got %q", resp["status"])
	}
}

func TestTestConnectionFromFormWebLink(t *testing.T) {
	tests := []struct {
		name       string
		formURL    string
		wantCode   int
		wantStatus string
	}{
		{"valid https", "https://portal.example.com", http.StatusOK, "success"},
		{"javascript scheme", "javascript:alert(1)", http.StatusBadRequest, "error"},
		{"scheme relative", "//evil.example.com", http.StatusBadRequest, "error"},
		{"empty", "", http.StatusBadRequest, "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := setupIDPTest(t)
			cookies := env.createAdminSession(t)

			v := url.Values{}
			v.Set("provider_type", "weblink")
			v.Set("weblink_url", tt.formURL)

			rec := env.serveWithAdminSession(t, env.handler.TestConnectionFromForm,
				http.MethodPost, "/admin/idp/test-connection", cookies, v.Encode())

			if rec.Code != tt.wantCode {
				t.Fatalf("expected %d, got %d (%s)", tt.wantCode, rec.Code, rec.Body.String())
			}
			var resp map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("parsing response: %v", err)
			}
			if resp["status"] != tt.wantStatus {
				t.Errorf("expected status %q, got %q", tt.wantStatus, resp["status"])
			}
		})
	}
}

func TestDirectoryIDPs_FiltersWebLinks(t *testing.T) {
	in := []db.IdentityProviderRecord{
		{ID: "ad-1", ProviderType: "ad"},
		{ID: "link-1", ProviderType: "weblink"},
		{ID: "ipa-1", ProviderType: "freeipa"},
		{ID: "odd-1", ProviderType: "unknown"},
	}

	got := directoryIDPs(in)
	if len(got) != 2 {
		t.Fatalf("expected 2 directory IDPs, got %d", len(got))
	}
	if got[0].ID != "ad-1" || got[1].ID != "ipa-1" {
		t.Errorf("unexpected filter result: %+v", got)
	}
}

func TestShowLogin_WebLinkCards(t *testing.T) {
	env := setupLoginTest(t)
	env.handler.renderer = weblinkLoginRenderer(t)

	env.createIDPRecord(t, "corp-ad", "Corp AD")
	seedWebLink(t, env.db, "portal", "Company Portal", `{"url":"https://portal.example.com"}`)
	seedWebLink(t, env.db, "unsafe", "Unsafe Link", `{"url":"javascript:alert(1)"}`)
	seedWebLink(t, env.db, "nourl", "No URL", `{}`)
	seedWebLink(t, env.db, "badjson", "Bad JSON", `not json`)

	rec := env.serveNoSession(t, env.handler.ShowLogin, http.MethodGet, "/login", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()

	if !strings.Contains(body, "Corp AD|") {
		t.Error("expected directory provider card to render")
	}
	if !strings.Contains(body, "Company Portal|https://portal.example.com") {
		t.Errorf("expected weblink card with URL, got %q", body)
	}
	for _, name := range []string{"Unsafe Link", "No URL", "Bad JSON"} {
		if strings.Contains(body, name) {
			t.Errorf("weblink %q has no usable URL and must not render a dead card", name)
		}
	}
}

func TestShowDashboard_WebLinksSeparatedFromPanels(t *testing.T) {
	env := setupDashboardTest(t)
	env.handler.renderer = weblinkDashboardRenderer(t)
	cookies := env.createSessionWithCookies(t, "provider", "corp-ad", "alice", false)

	seedDirectoryIDP(t, env.db, "corp-ad", "Corp AD")
	seedWebLink(t, env.db, "portal", "Company Portal", `{"url":"https://portal.example.com"}`)
	seedWebLink(t, env.db, "unsafe", "Unsafe Link", `{"url":"javascript:alert(1)"}`)

	rec := env.serveWithSession(t, env.handler.ShowDashboard, http.MethodGet, "/dashboard", cookies, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()

	if !strings.Contains(body, "panel:Corp AD") {
		t.Error("expected directory provider to render as a password panel")
	}
	if strings.Contains(body, "panel:Company Portal") {
		t.Error("weblink must not render as a password-management panel")
	}
	if !strings.Contains(body, "link:Company Portal=https://portal.example.com") {
		t.Errorf("expected weblink to render as a link, got %q", body)
	}
	if strings.Contains(body, "Unsafe Link") {
		t.Error("weblink with an unsafe URL must be dropped entirely")
	}
}

func seedWebLink(t *testing.T, database *db.DB, id, name, configJSON string) {
	t.Helper()
	rec := &db.IdentityProviderRecord{
		ID:           id,
		FriendlyName: name,
		ProviderType: string(idp.ProviderTypeWebLink),
		Enabled:      true,
		ConfigJSON:   configJSON,
	}
	if err := database.CreateIDP(context.Background(), rec); err != nil {
		t.Fatalf("creating weblink IDP %q: %v", id, err)
	}
}

func seedDirectoryIDP(t *testing.T, database *db.DB, id, name string) {
	t.Helper()
	rec := &db.IdentityProviderRecord{
		ID:           id,
		FriendlyName: name,
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   `{"endpoint":"ldap.example.com:636","protocol":"ldaps"}`,
	}
	if err := database.CreateIDP(context.Background(), rec); err != nil {
		t.Fatalf("creating directory IDP %q: %v", id, err)
	}
}

func weblinkLoginRenderer(t *testing.T) *Renderer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pages := map[string]*template.Template{
		"login.html": template.Must(template.New("login.html").Parse(
			`{{define "base"}}{{range .Data.Sections}}{{range .IDPs}}{{.FriendlyName}}|{{.WebLinkURL}} {{end}}{{end}}{{end}}`)),
		"error.html": template.Must(template.New("error.html").Parse(`{{define "base"}}error{{end}}`)),
	}
	return &Renderer{pages: pages, logger: logger}
}

func weblinkDashboardRenderer(t *testing.T) *Renderer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pages := map[string]*template.Template{
		"dashboard.html": template.Must(template.New("dashboard.html").Parse(
			`{{define "base"}}{{range .Data.Sections}}{{range .Panels}}panel:{{.IDP.FriendlyName}} {{end}}` +
				`{{range .Links}}link:{{.IDP.FriendlyName}}={{.URL}} {{end}}{{end}}{{end}}`)),
		"error.html": template.Must(template.New("error.html").Parse(`{{define "base"}}error{{end}}`)),
		"login.html": template.Must(template.New("login.html").Parse(`{{define "base"}}login{{end}}`)),
	}
	return &Renderer{pages: pages, logger: logger}
}
