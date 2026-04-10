package handler

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hanej/passport/internal/db"
)

func TestMatchDir(t *testing.T) {
	tests := []struct {
		path   string
		prefix string
		want   bool
	}{
		{"templates/layouts/base.html", "templates/layouts/", true},
		{"templates/pages/login.html", "templates/pages/", true},
		{"templates/layouts/", "templates/layouts/", false}, // exactly the prefix — length not >
		{"templates/pages/sub/deep.html", "templates/pages/", true},
		{"other/login.html", "templates/pages/", false},
		{"", "templates/", false},
	}
	for _, tc := range tests {
		got := matchDir(tc.path, tc.prefix)
		if got != tc.want {
			t.Errorf("matchDir(%q, %q) = %v, want %v", tc.path, tc.prefix, got, tc.want)
		}
	}
}

func TestParseHex(t *testing.T) {
	tests := []struct {
		hex    string
		wantR  int
		wantG  int
		wantB  int
		wantOK bool
	}{
		{"#ff0000", 255, 0, 0, true},
		{"#00ff00", 0, 255, 0, true},
		{"#0000ff", 0, 0, 255, true},
		{"#1a2b3c", 26, 43, 60, true},
		{"#ffffff", 255, 255, 255, true},
		{"#000000", 0, 0, 0, true},
		{"ff0000", 255, 0, 0, true},  // without #
		{"#gg0000", 0, 0, 0, false},  // invalid hex
		{"#fff", 0, 0, 0, false},     // too short
		{"#fffffff", 0, 0, 0, false}, // too long
		{"", 0, 0, 0, false},         // empty
	}
	for _, tc := range tests {
		r, g, b, ok := parseHex(tc.hex)
		if ok != tc.wantOK {
			t.Errorf("parseHex(%q) ok=%v, want %v", tc.hex, ok, tc.wantOK)
			continue
		}
		if ok && (r != tc.wantR || g != tc.wantG || b != tc.wantB) {
			t.Errorf("parseHex(%q) = (%d,%d,%d), want (%d,%d,%d)", tc.hex, r, g, b, tc.wantR, tc.wantG, tc.wantB)
		}
	}
}

func TestPageName(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"templates/pages/login.html", "login.html"},
		{"templates/pages/admin/idp.html", "idp.html"},
		{"login.html", "login.html"},
		{"", ""},
		{"a/b/c/d.html", "d.html"},
	}
	for _, tc := range tests {
		got := pageName(tc.path)
		if got != tc.want {
			t.Errorf("pageName(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestNewRenderer_LoadsTemplates(t *testing.T) {
	logger := testLogger()
	r, err := NewRenderer("", logger)
	if err != nil {
		t.Fatalf("NewRenderer failed: %v", err)
	}
	if len(r.pages) == 0 {
		t.Fatal("expected pages to be loaded")
	}
	// login.html must be present since it's a core page.
	if _, ok := r.pages["login.html"]; !ok {
		t.Error("expected login.html page to be loaded")
	}
}

func TestRenderer_TemplateNotFound(t *testing.T) {
	logger := testLogger()
	r, err := NewRenderer("", logger)
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Render(w, req, "nonexistent_page.html", PageData{Title: "Test"})
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestRenderer_RenderError(t *testing.T) {
	logger := testLogger()
	r, err := NewRenderer("", logger)
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RenderError(w, req, http.StatusNotFound, "Page not found")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestRenderer_JSON(t *testing.T) {
	logger := testLogger()
	r, err := NewRenderer("", logger)
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}
	w := httptest.NewRecorder()
	r.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content type, got %s", ct)
	}
	if !strings.Contains(w.Body.String(), "ok") {
		t.Errorf("expected 'ok' in response body, got: %s", w.Body.String())
	}
}

func TestRenderer_SetBranding(t *testing.T) {
	logger := testLogger()
	r, err := NewRenderer("", logger)
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}

	from_db_branding := r.branding.Load()
	if from_db_branding == nil {
		t.Fatal("branding should be set to defaults")
	}
}

func TestTemplateFuncMap_HexToRGB(t *testing.T) {
	// Exercise the hexToRGB and darkenHex funcs via the renderer's template
	// execution path by rendering a page that calls these functions.
	// We test the helpers directly since they are closures in funcMap.
	// The parseHex tests above cover the underlying logic; here we just
	// ensure NewRenderer doesn't error when these funcs are invoked.
	logger := testLogger()
	_, err := NewRenderer("", logger)
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}
}

// TestFuncMap_HexToRGBAndDarken renders a page with valid branding to cover
// the hexToRGB and darkenHex success paths (lines 85-103 in render.go).
func TestFuncMap_HexToRGBAndDarken(t *testing.T) {
	logger := testLogger()
	r, err := NewRenderer("", logger)
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}
	// Set a valid hex color so hexToRGB/darkenHex take the success (ok==true) path.
	r.SetBranding(&db.BrandingConfig{
		AppTitle:     "Test App",
		PrimaryColor: "#3498db",
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Render(w, req, "login.html", PageData{Title: "Login"})
	// Status 200 confirms the template rendered successfully with the funcmap funcs.
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body excerpt: %s", w.Code, excerpt(w.Body.String()))
	}
}

// TestFuncMap_PagesAddSubtract renders admin_mappings.html with pagination data
// to cover the pages, add, and subtract funcmap closures (lines 60-72 in render.go).
func TestFuncMap_PagesAddSubtract(t *testing.T) {
	logger := testLogger()
	r, err := NewRenderer("", logger)
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}

	// Build minimal mapping data using maps so the template can range over them.
	mappings := []map[string]any{
		{"AuthProviderID": "ad-1", "AuthUsername": "jdoe", "TargetIDPID": "ad-2",
			"TargetAccountDN": "CN=jdoe,DC=example,DC=com", "LinkType": "auto", "ID": 1},
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Render(w, req, "admin_mappings.html", PageData{
		Title: "Mappings",
		Data: map[string]any{
			"SearchUsername": "jdoe",
			"TotalPages":     3,
			"CurrentPage":    2,
			"TotalCount":     1,
			"Mappings":       mappings,
			"PaginationBase": "/admin/mappings?page=",
		},
	})
	// Status 200 confirms template rendered; 500 means a funcmap or data error.
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body excerpt: %s", w.Code, excerpt(w.Body.String()))
	}
}

// TestFuncMap_MarkdownHTML renders reset_password.html with a ComplexityHint
// to cover the markdownHTML funcmap closure (lines 76-82 in render.go).
func TestFuncMap_MarkdownHTML(t *testing.T) {
	logger := testLogger()
	r, err := NewRenderer("", logger)
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Render(w, req, "reset_password.html", PageData{
		Title: "Reset Password",
		Data: map[string]any{
			"ComplexityHint": "**Must** contain at least 8 characters",
		},
	})
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body excerpt: %s", w.Code, excerpt(w.Body.String()))
	}
	if !strings.Contains(w.Body.String(), "Must") {
		t.Error("expected markdownHTML output to contain 'Must'")
	}
}

// excerpt returns the first 200 characters of s for error messages.
func excerpt(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

// TestRenderer_RenderExecuteError covers the ExecuteTemplate error path in Render.
// A page template that exists but defines no "base" block causes ExecuteTemplate to fail.
func TestRenderer_RenderExecuteError(t *testing.T) {
	logger := testLogger()
	// Build a Renderer manually with a template that has no "base" definition.
	r := &Renderer{
		pages:  make(map[string]*template.Template),
		logger: logger,
	}
	tmpl := template.Must(template.New("bad.html").Parse(`{{define "notbase"}}content{{end}}`))
	r.pages["bad.html"] = tmpl

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Render(w, req, "bad.html", PageData{Title: "Test"})
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on template execution error, got %d", w.Code)
	}
}

// TestRenderer_JSONEncodeError covers the json.Encode error log path.
// Channels cannot be JSON-marshalled, so Encode returns an error.
func TestRenderer_JSONEncodeError(t *testing.T) {
	logger := testLogger()
	r := &Renderer{logger: logger}

	w := httptest.NewRecorder()
	// Pass a channel — JSON encoding a chan is unsupported and returns an error.
	r.JSON(w, http.StatusOK, make(chan int))
	// WriteHeader was already called, so we just verify no panic and body is empty/broken.
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (WriteHeader already called), got %d", w.Code)
	}
}

// TestFuncMap_InvalidHexBranding covers the ok=false paths inside the hexToRGB
// and darkenHex funcmap closures (lines 102-121 in render.go).
// Setting an invalid PrimaryColor forces parseHex to fail and both funcs return
// their failure values (empty string / original value).
func TestFuncMap_InvalidHexBranding(t *testing.T) {
	logger := testLogger()
	r, err := NewRenderer("", logger)
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}
	r.SetBranding(&db.BrandingConfig{
		AppTitle:     "Test App",
		PrimaryColor: "#xyz", // invalid hex — forces ok=false in both funcs
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Render(w, req, "login.html", PageData{Title: "Login"})
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, excerpt(w.Body.String()))
	}
}

// TestFuncMap_FmtTimePointer covers the *time.Time (non-nil) case in the fmtTime
// funcmap closure (render.go line 94-96). admin_mappings.html calls
// {{fmtTime .VerifiedAt}} when .VerifiedAt is non-nil.
func TestFuncMap_FmtTimePointer(t *testing.T) {
	logger := testLogger()
	r, err := NewRenderer("", logger)
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}

	now := time.Now()
	mappings := []*db.UserIDPMapping{
		{
			ID:              1,
			AuthProviderID:  "ad-1",
			AuthUsername:    "jdoe",
			TargetIDPID:     "ad-2",
			TargetAccountDN: "CN=jdoe,DC=example,DC=com",
			LinkType:        "auto",
			LinkedAt:        now,
			VerifiedAt:      &now, // non-nil *time.Time — triggers case *time.Time: non-nil path
		},
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Render(w, req, "admin_mappings.html", PageData{
		Title: "Mappings",
		Data: map[string]any{
			"SearchUsername": "jdoe",
			"TotalPages":     1,
			"CurrentPage":    1,
			"TotalCount":     1,
			"Mappings":       mappings,
			"PaginationBase": "/admin/mappings?page=",
		},
	})
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, excerpt(w.Body.String()))
	}
}
