package handler

import (
	"bytes"
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
)

type emailTemplatesTestEnv struct {
	db      *db.DB
	handler *AdminEmailTemplatesHandler
	sm      *auth.SessionManager
	audit   *audit.Logger
}

func stubEmailTemplatesRenderer(t *testing.T) *Renderer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	funcMap := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"pages":    func(n int) []int { return nil },
	}
	pages := make(map[string]*template.Template)
	pages["admin_email_templates.html"] = template.Must(template.New("admin_email_templates.html").Funcs(funcMap).Parse(`{{define "base"}}email templates list{{end}}`))
	pages["admin_email_template_form.html"] = template.Must(template.New("admin_email_template_form.html").Funcs(funcMap).Parse(`{{define "base"}}email template form{{end}}`))
	pages["error.html"] = template.Must(template.New("error.html").Funcs(funcMap).Parse(`{{define "base"}}error page{{end}}`))
	return &Renderer{pages: pages, logger: logger}
}

func setupEmailTemplatesTest(t *testing.T) *emailTemplatesTestEnv {
	t.Helper()

	database := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := stubEmailTemplatesRenderer(t)

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

	h := NewAdminEmailTemplatesHandler(database, renderer, sm, auditLog, logger)

	return &emailTemplatesTestEnv{
		db:      database,
		handler: h,
		sm:      sm,
		audit:   auditLog,
	}
}

func (env *emailTemplatesTestEnv) createAdminSession(t *testing.T) []*http.Cookie {
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

func (env *emailTemplatesTestEnv) serveWithAdminSession(t *testing.T, handler http.HandlerFunc, method, path string, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
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

// --- Unit tests for pure functions ---

func TestIsPasswordExpirationTemplate(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"password_expiration", true},
		{"password_expiration:idp1", true},
		{"password_expiration:corp-ad", true},
		{"password_expiration:", true}, // edge case: prefix matches
		{"password_reset", false},
		{"smtp_test", false},
		{"other", false},
		{"", false},
	}
	for _, tc := range tests {
		got := IsPasswordExpirationTemplate(tc.input)
		if got != tc.want {
			t.Errorf("IsPasswordExpirationTemplate(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestExecuteTemplate_Valid(t *testing.T) {
	tmplStr := `<p>Hello {{.Username}}, your provider is {{.ProviderName}}.</p>`
	data := map[string]string{
		"Username":     "John Doe",
		"ProviderName": "Corporate AD",
	}

	result, err := executeTemplate(tmplStr, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "John Doe") {
		t.Errorf("expected 'John Doe' in output, got: %s", result)
	}
	if !strings.Contains(result, "Corporate AD") {
		t.Errorf("expected 'Corporate AD' in output, got: %s", result)
	}
}

func TestExecuteTemplate_InvalidSyntax(t *testing.T) {
	tmplStr := `<p>{{.Username</p>` // missing closing brace
	_, err := executeTemplate(tmplStr, map[string]string{})
	if err == nil {
		t.Error("expected error for invalid template syntax")
	}
}

func TestExecuteTemplate_EmptyTemplate(t *testing.T) {
	result, err := executeTemplate("", map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error on empty template: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty result, got: %s", result)
	}
}

// --- Handler tests ---

func TestAdminEmailTemplatesList_Empty(t *testing.T) {
	env := setupEmailTemplatesTest(t)
	cookies := env.createAdminSession(t)

	rec := env.serveWithAdminSession(t, env.handler.List, http.MethodGet, "/admin/email-templates", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "email templates list") {
		t.Errorf("expected email templates list content, got: %s", rec.Body.String())
	}
}

func TestAdminEmailTemplatesList_WithItems(t *testing.T) {
	env := setupEmailTemplatesTest(t)
	ctx := context.Background()

	// Insert a couple of templates.
	for _, tt := range []struct{ tp, subj, body string }{
		{"smtp_test", "SMTP Test", "<p>Test</p>"},
		{"password_reset", "Password Reset", "<p>Reset</p>"},
	} {
		if err := env.db.SaveEmailTemplate(ctx, &db.EmailTemplate{
			TemplateType: tt.tp,
			Subject:      tt.subj,
			BodyHTML:     tt.body,
		}); err != nil {
			t.Fatalf("saving template %s: %v", tt.tp, err)
		}
	}

	cookies := env.createAdminSession(t)
	rec := env.serveWithAdminSession(t, env.handler.List, http.MethodGet, "/admin/email-templates", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestAdminEmailTemplatesEdit(t *testing.T) {
	env := setupEmailTemplatesTest(t)
	ctx := context.Background()
	cookies := env.createAdminSession(t)

	// Pre-seed the template so Edit can load it.
	if err := env.db.SaveEmailTemplate(ctx, &db.EmailTemplate{
		TemplateType: "password_expiration",
		Subject:      "Expiring Soon",
		BodyHTML:     `<p>Hello {{.Username}}</p>`,
	}); err != nil {
		t.Fatalf("saving template: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "type", "password_expiration")
		env.handler.Edit(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/email-templates/password_expiration/edit", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "email template form") {
		t.Errorf("expected email template form content, got: %s", rec.Body.String())
	}
}

func TestAdminEmailTemplatesEdit_NotFound(t *testing.T) {
	env := setupEmailTemplatesTest(t)
	cookies := env.createAdminSession(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "type", "nonexistent_template")
		env.handler.Edit(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/email-templates/nonexistent_template/edit", cookies, "")

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}

func TestAdminEmailTemplatesSave(t *testing.T) {
	env := setupEmailTemplatesTest(t)
	ctx := context.Background()
	cookies := env.createAdminSession(t)

	// Pre-seed so the type is valid.
	if err := env.db.SaveEmailTemplate(ctx, &db.EmailTemplate{
		TemplateType: "smtp_test",
		Subject:      "Old Subject",
		BodyHTML:     "<p>Old</p>",
	}); err != nil {
		t.Fatalf("saving template: %v", err)
	}

	form := url.Values{}
	form.Set("subject", "New Subject")
	form.Set("body_html", "<p>New body {{.Timestamp}}</p>")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "type", "smtp_test")
		env.handler.Save(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/email-templates/smtp_test", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302 (redirect), got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/email-templates" {
		t.Errorf("expected redirect to /admin/email-templates, got %s", loc)
	}

	// Verify the template was updated.
	tmpl, err := env.db.GetEmailTemplate(ctx, "smtp_test")
	if err != nil {
		t.Fatalf("getting template: %v", err)
	}
	if tmpl.Subject != "New Subject" {
		t.Errorf("expected subject 'New Subject', got %q", tmpl.Subject)
	}
}

func TestAdminEmailTemplatesDelete(t *testing.T) {
	env := setupEmailTemplatesTest(t)
	ctx := context.Background()
	cookies := env.createAdminSession(t)

	// Per-IDP templates (containing ":") can be deleted.
	if err := env.db.SaveEmailTemplate(ctx, &db.EmailTemplate{
		TemplateType: "password_expiration:corp-ad",
		Subject:      "Expiring for corp-ad",
		BodyHTML:     "<p>Expires soon</p>",
	}); err != nil {
		t.Fatalf("saving per-IDP template: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "type", "password_expiration:corp-ad")
		env.handler.Delete(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/email-templates/password_expiration:corp-ad/delete", cookies, "")

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminEmailTemplatesDelete_GlobalBlocked(t *testing.T) {
	env := setupEmailTemplatesTest(t)
	cookies := env.createAdminSession(t)

	// Attempting to delete a global template (no ":") should redirect with error flash.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "type", "smtp_test")
		env.handler.Delete(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/email-templates/smtp_test/delete", cookies, "")

	// Should redirect back to list (not delete anything).
	if rec.Code != http.StatusFound {
		t.Errorf("expected status 302 (redirect with error), got %d", rec.Code)
	}
}

func TestAdminEmailTemplatesPreview(t *testing.T) {
	env := setupEmailTemplatesTest(t)

	body := previewRequest{
		TemplateType: "password_expiration",
		Subject:      "Your password expires in {{.DaysRemaining}} days",
		BodyHTML:     `<p>Hello {{.Username}}, expiring on {{.ExpirationDate}}</p>`,
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshaling request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/email-templates/preview", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	env.handler.Preview(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON response: %v", err)
	}
	if _, ok := result["rendered_html"]; !ok {
		t.Errorf("expected 'rendered_html' in response, got: %v", result)
	}
	if _, ok := result["rendered_subject"]; !ok {
		t.Errorf("expected 'rendered_subject' in response, got: %v", result)
	}
	renderedHTML, _ := result["rendered_html"].(string)
	if !strings.Contains(renderedHTML, "John Doe") {
		t.Errorf("expected rendered HTML to contain sample data 'John Doe', got: %s", renderedHTML)
	}
}

func TestAdminEmailTemplatesPreview_InvalidJSON(t *testing.T) {
	env := setupEmailTemplatesTest(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/email-templates/preview", strings.NewReader(`{invalid`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	env.handler.Preview(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}
}

func TestAdminEmailTemplatesPreview_InvalidTemplate(t *testing.T) {
	env := setupEmailTemplatesTest(t)

	body := previewRequest{
		TemplateType: "smtp_test",
		Subject:      "Test",
		BodyHTML:     `<p>{{.Unclosed</p>`, // invalid template
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/email-templates/preview", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	env.handler.Preview(rec, req)

	// On template error the handler returns 200 with an "error" field in JSON.
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 with error JSON, got %d", rec.Code)
	}
	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON response: %v", err)
	}
	if _, ok := result["error"]; !ok {
		t.Errorf("expected 'error' key in JSON response, got: %v", result)
	}
}

func TestAdminEmailTemplatesResetDefault(t *testing.T) {
	env := setupEmailTemplatesTest(t)
	ctx := context.Background()
	cookies := env.createAdminSession(t)

	// Overwrite the smtp_test template with custom content.
	if err := env.db.SaveEmailTemplate(ctx, &db.EmailTemplate{
		TemplateType: "smtp_test",
		Subject:      "Custom Subject",
		BodyHTML:     "<p>Custom</p>",
	}); err != nil {
		t.Fatalf("saving template: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "type", "smtp_test")
		env.handler.ResetDefault(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/email-templates/smtp_test/reset", cookies, "")

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302 (redirect after reset), got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify the template was restored to the default.
	tmpl, err := env.db.GetEmailTemplate(ctx, "smtp_test")
	if err != nil {
		t.Fatalf("getting template after reset: %v", err)
	}
	def := defaultTemplates["smtp_test"]
	if tmpl.Subject != def.Subject {
		t.Errorf("expected default subject %q, got %q", def.Subject, tmpl.Subject)
	}
}

func TestAdminEmailTemplatesResetDefault_InvalidType(t *testing.T) {
	env := setupEmailTemplatesTest(t)
	cookies := env.createAdminSession(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "type", "nonexistent")
		env.handler.ResetDefault(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/email-templates/nonexistent/reset", cookies, "")

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404 for unknown template type, got %d", rec.Code)
	}
}

func TestAdminEmailTemplatesSave_InvalidType(t *testing.T) {
	env := setupEmailTemplatesTest(t)
	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("subject", "Test")
	form.Set("body_html", "<p>Test</p>")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "type", "not_a_real_template")
		env.handler.Save(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/email-templates/not_a_real_template", cookies, form.Encode())

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404 for invalid type, got %d", rec.Code)
	}
}

func TestAdminEmailTemplatesEdit_PerIDPFallback(t *testing.T) {
	// A per-IDP expiration template that doesn't exist should fall back to
	// the global password_expiration template if that exists.
	env := setupEmailTemplatesTest(t)
	ctx := context.Background()
	cookies := env.createAdminSession(t)

	// Seed the global template (which the per-IDP template falls back to).
	if err := env.db.SaveEmailTemplate(ctx, &db.EmailTemplate{
		TemplateType: "password_expiration",
		Subject:      "Global Expiry Subject",
		BodyHTML:     "<p>Global expiry</p>",
	}); err != nil {
		t.Fatalf("saving global template: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "type", "password_expiration:corp-ad")
		env.handler.Edit(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/email-templates/password_expiration:corp-ad/edit", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 (fallback to global), got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// Verify the UpdatedAt field is populated in list results.
func TestAdminEmailTemplatesListUpdatedAt(t *testing.T) {
	env := setupEmailTemplatesTest(t)
	ctx := context.Background()

	if err := env.db.SaveEmailTemplate(ctx, &db.EmailTemplate{
		TemplateType: "account_locked",
		Subject:      "Account Locked",
		BodyHTML:     "<p>Locked</p>",
	}); err != nil {
		t.Fatalf("saving template: %v", err)
	}

	templates, err := env.db.ListEmailTemplates(ctx)
	if err != nil {
		t.Fatalf("listing templates: %v", err)
	}
	if len(templates) == 0 {
		t.Fatal("expected at least one template")
	}

	for _, tmpl := range templates {
		if tmpl.UpdatedAt.IsZero() {
			t.Errorf("template %s has zero UpdatedAt", tmpl.TemplateType)
		}
	}
}

// TestAdminEmailTemplatesList_PerIDPTemplate verifies that List generates the
// correct friendly name for a per-IDP password expiration template
// (lines 133-136 in admin_email_templates.go).
func TestAdminEmailTemplatesList_PerIDPTemplate(t *testing.T) {
	env := setupEmailTemplatesTest(t)
	ctx := context.Background()

	if err := env.db.SaveEmailTemplate(ctx, &db.EmailTemplate{
		TemplateType: "password_expiration:corp-ad",
		Subject:      "Expiry for corp-ad",
		BodyHTML:     "<p>Expires soon</p>",
	}); err != nil {
		t.Fatalf("saving per-IDP template: %v", err)
	}

	cookies := env.createAdminSession(t)
	rec := env.serveWithAdminSession(t, env.handler.List, http.MethodGet, "/admin/email-templates", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminEmailTemplatesList_UnknownType verifies that List uses the type
// string itself as the friendly name when no match is found (lines 137-139).
func TestAdminEmailTemplatesList_UnknownType(t *testing.T) {
	env := setupEmailTemplatesTest(t)
	ctx := context.Background()

	// Insert a template with a type not in templateNames and not a per-IDP
	// expiration, so the name falls back to the raw type.
	if err := env.db.SaveEmailTemplate(ctx, &db.EmailTemplate{
		TemplateType: "custom_unknown_type",
		Subject:      "Custom",
		BodyHTML:     "<p>Custom</p>",
	}); err != nil {
		t.Fatalf("saving custom template: %v", err)
	}

	cookies := env.createAdminSession(t)
	rec := env.serveWithAdminSession(t, env.handler.List, http.MethodGet, "/admin/email-templates", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminEmailTemplatesEdit_TemplateDeletedFromDB verifies that Edit returns
// 500 when a valid template type exists in templateVariables but its row has
// been deleted from the database (lines 192-196).
func TestAdminEmailTemplatesEdit_TemplateDeletedFromDB(t *testing.T) {
	env := setupEmailTemplatesTest(t)
	ctx := context.Background()
	cookies := env.createAdminSession(t)

	// The migrations seed smtp_test; delete it so the DB returns ErrNotFound.
	if err := env.db.DeleteEmailTemplate(ctx, "smtp_test"); err != nil {
		t.Fatalf("deleting seeded template: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "type", "smtp_test")
		env.handler.Edit(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/email-templates/smtp_test/edit", cookies, "")

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500 for deleted template, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminEmailTemplatesEdit_PerIDPNoGlobal verifies that Edit returns 500
// when a per-IDP expiration template doesn't exist and neither does the global
// password_expiration template (lines 192-196).
func TestAdminEmailTemplatesEdit_PerIDPNoGlobal(t *testing.T) {
	env := setupEmailTemplatesTest(t)
	ctx := context.Background()
	cookies := env.createAdminSession(t)

	// Delete the global password_expiration template so the fallback also fails.
	if err := env.db.DeleteEmailTemplate(ctx, "password_expiration"); err != nil {
		t.Fatalf("deleting global template: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "type", "password_expiration:new-idp")
		env.handler.Edit(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/email-templates/password_expiration:new-idp/edit", cookies, "")

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500 when global fallback is also absent, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminEmailTemplatesPreview_InvalidSubject verifies that Preview returns
// 200 with an error JSON when the subject template is invalid
// (lines 385-387 in admin_email_templates.go).
func TestAdminEmailTemplatesPreview_InvalidSubject(t *testing.T) {
	env := setupEmailTemplatesTest(t)

	body := previewRequest{
		TemplateType: "smtp_test",
		Subject:      `{{.Unclosed`, // invalid subject template
		BodyHTML:     `<p>Valid body</p>`,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/email-templates/preview", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	env.handler.Preview(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 with error JSON, got %d", rec.Code)
	}
	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON response: %v", err)
	}
	if _, ok := result["error"]; !ok {
		t.Errorf("expected 'error' key in JSON response for invalid subject, got: %v", result)
	}
}

func TestExecuteTemplate_AllSampleVars(t *testing.T) {
	// Verify all standard variable names used in the Preview endpoint are accessible.
	tmplStr := `{{.Username}} {{.ProviderName}} {{.Timestamp}} {{.IPAddress}} {{.ExpirationDate}} {{.DaysRemaining}} {{.Reason}}`
	data := map[string]string{
		"Username":       "Jane Smith",
		"ProviderName":   "LDAP",
		"Timestamp":      "Jan 1, 2026 9:00 AM MST",
		"IPAddress":      "10.0.0.1",
		"ExpirationDate": "Mar 1, 2026",
		"DaysRemaining":  "14",
		"Reason":         "Brute force",
	}

	result, err := executeTemplate(tmplStr, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, expected := range []string{"Jane Smith", "LDAP", "10.0.0.1", "14", "Brute force"} {
		if !strings.Contains(result, expected) {
			t.Errorf("expected %q in output, got: %s", expected, result)
		}
	}
}

// mockEmailTemplatesErrStore wraps *db.DB and overrides specific methods to inject errors.
type mockEmailTemplatesErrStore struct {
	*db.DB
	listTemplatesErr  error
	saveTemplateErr   error
	deleteTemplateErr error
}

func (m *mockEmailTemplatesErrStore) ListEmailTemplates(ctx context.Context) ([]db.EmailTemplate, error) {
	if m.listTemplatesErr != nil {
		return nil, m.listTemplatesErr
	}
	return m.DB.ListEmailTemplates(ctx)
}

func (m *mockEmailTemplatesErrStore) SaveEmailTemplate(ctx context.Context, tmpl *db.EmailTemplate) error {
	if m.saveTemplateErr != nil {
		return m.saveTemplateErr
	}
	return m.DB.SaveEmailTemplate(ctx, tmpl)
}

func (m *mockEmailTemplatesErrStore) DeleteEmailTemplate(ctx context.Context, templateType string) error {
	if m.deleteTemplateErr != nil {
		return m.deleteTemplateErr
	}
	return m.DB.DeleteEmailTemplate(ctx, templateType)
}

func newEmailTemplatesMockHandler(t *testing.T, database *db.DB, mock *mockEmailTemplatesErrStore) *AdminEmailTemplatesHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := stubEmailTemplatesRenderer(t)
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
	return NewAdminEmailTemplatesHandler(mock, renderer, sm, auditLog, logger)
}

// TestAdminEmailTemplatesList_DBError covers List when ListEmailTemplates fails (lines 117-121).
func TestAdminEmailTemplatesList_DBError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockEmailTemplatesErrStore{DB: database, listTemplatesErr: fmt.Errorf("DB read failed")}
	h := newEmailTemplatesMockHandler(t, database, mock)

	req := httptest.NewRequest(http.MethodGet, "/admin/email-templates", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when ListEmailTemplates fails, got %d", rec.Code)
	}
}

// TestAdminEmailTemplatesSave_DBError covers Save when SaveEmailTemplate fails (lines 247-251).
func TestAdminEmailTemplatesSave_DBError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockEmailTemplatesErrStore{DB: database, saveTemplateErr: fmt.Errorf("DB write failed")}
	h := newEmailTemplatesMockHandler(t, database, mock)

	form := url.Values{}
	form.Set("subject", "Test Subject")
	form.Set("body_html", "<p>Test</p>")

	req := httptest.NewRequest(http.MethodPost, "/admin/email-templates/smtp_test", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withChiURLParam(req, "type", "smtp_test")
	rec := httptest.NewRecorder()
	h.Save(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when SaveEmailTemplate fails, got %d", rec.Code)
	}
}

// TestAdminEmailTemplatesDelete_DBError covers Delete when DeleteEmailTemplate fails (lines 286-291).
func TestAdminEmailTemplatesDelete_DBError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockEmailTemplatesErrStore{DB: database, deleteTemplateErr: fmt.Errorf("DB delete failed")}
	h := newEmailTemplatesMockHandler(t, database, mock)

	req := httptest.NewRequest(http.MethodPost, "/admin/email-templates/password_expiration:corp-ad/delete", nil)
	req = withChiURLParam(req, "type", "password_expiration:corp-ad")
	rec := httptest.NewRecorder()
	h.Delete(rec, req)

	// Delete error redirects back to list (302) with flash.
	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 redirect when DeleteEmailTemplate fails, got %d", rec.Code)
	}
}

// TestAdminEmailTemplatesResetDefault_DBError covers ResetDefault when SaveEmailTemplate fails (lines 412-416).
func TestAdminEmailTemplatesResetDefault_DBError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockEmailTemplatesErrStore{DB: database, saveTemplateErr: fmt.Errorf("DB write failed")}
	h := newEmailTemplatesMockHandler(t, database, mock)

	req := httptest.NewRequest(http.MethodPost, "/admin/email-templates/smtp_test/reset", nil)
	req = withChiURLParam(req, "type", "smtp_test")
	rec := httptest.NewRecorder()
	h.ResetDefault(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when SaveEmailTemplate fails in ResetDefault, got %d", rec.Code)
	}
}

// TestExecuteTemplate_ExecuteError covers the t.Execute error branch.
// {{template "missing"}} parses fine but fails at execute time (template not found).
func TestExecuteTemplate_ExecuteError(t *testing.T) {
	// This template references "missing_sub" which is not defined in this template set.
	// html/template Execute returns an error in this case.
	_, err := executeTemplate(`{{template "missing_sub"}}`, map[string]string{})
	if err == nil {
		t.Error("expected error from executeTemplate with undefined sub-template")
	}
}

// TestAdminEmailTemplatesSave_ParseFormError covers Save when ParseForm fails → 400.
func TestAdminEmailTemplatesSave_ParseFormError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockEmailTemplatesErrStore{DB: database}
	h := newEmailTemplatesMockHandler(t, database, mock)

	req := httptest.NewRequest(http.MethodPost, "/admin/email-templates/smtp_test", errReader{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withChiURLParam(req, "type", "smtp_test")
	rec := httptest.NewRecorder()
	h.Save(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when ParseForm fails, got %d", rec.Code)
	}
}
