package handler

import (
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func stubDocsRenderer(t *testing.T) *Renderer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	funcMap := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"pages":    func(n int) []int { return nil },
	}
	pages := make(map[string]*template.Template)
	pages["admin_docs.html"] = template.Must(template.New("admin_docs.html").Funcs(funcMap).Parse(`{{define "base"}}docs page{{end}}`))
	pages["error.html"] = template.Must(template.New("error.html").Funcs(funcMap).Parse(`{{define "base"}}error page{{end}}`))
	return &Renderer{pages: pages, logger: logger}
}

func TestAdminDocsShow_OK(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	renderer := stubDocsRenderer(t)

	docContent := []byte("# Documentation\n\nThis is the **admin guide**.")
	h := NewAdminDocsHandler(renderer, logger, docContent)

	req := httptest.NewRequest(http.MethodGet, "/admin/docs", nil)
	rec := httptest.NewRecorder()
	h.Show(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "docs page") {
		t.Errorf("expected docs page content, got: %s", rec.Body.String())
	}
}

func TestAdminDocsShow_EmptyContent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	renderer := stubDocsRenderer(t)

	// Empty markdown should still render without error.
	h := NewAdminDocsHandler(renderer, logger, []byte{})

	req := httptest.NewRequest(http.MethodGet, "/admin/docs", nil)
	rec := httptest.NewRecorder()
	h.Show(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestAdminDocsShow_MarkdownConvertedToHTML(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Use a renderer whose template outputs the Data.Content so we can verify
	// the rendered HTML is stored on the handler.
	funcMap := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"pages":    func(n int) []int { return nil },
	}
	pages := make(map[string]*template.Template)
	// Template outputs the Content field as a string for inspection.
	pages["admin_docs.html"] = template.Must(template.New("admin_docs.html").Funcs(funcMap).Parse(
		`{{define "base"}}{{if .Data}}{{with index .Data "Content"}}{{.}}{{end}}{{end}}{{end}}`,
	))
	pages["error.html"] = template.Must(template.New("error.html").Funcs(funcMap).Parse(`{{define "base"}}error page{{end}}`))

	rendererWithOutput := &Renderer{pages: pages, logger: logger}

	// Goldmark should convert this to an <h1> tag.
	docContent := []byte("# Admin Guide\n\nHello world.")
	h := NewAdminDocsHandler(rendererWithOutput, logger, docContent)

	req := httptest.NewRequest(http.MethodGet, "/admin/docs", nil)
	rec := httptest.NewRecorder()
	h.Show(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<h1") {
		t.Errorf("expected rendered HTML with <h1>, got: %s", body)
	}
	if !strings.Contains(body, "Admin Guide") {
		t.Errorf("expected 'Admin Guide' in rendered output, got: %s", body)
	}
}

func TestAdminDocsShow_NoSessionOK(t *testing.T) {
	// Show must work even without a session in context (sess is nil).
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	renderer := stubDocsRenderer(t)

	h := NewAdminDocsHandler(renderer, logger, []byte("# Docs"))

	req := httptest.NewRequest(http.MethodGet, "/admin/docs", nil)
	// No session middleware, no cookies — sess will be nil.
	rec := httptest.NewRecorder()
	h.Show(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 without session, got %d", rec.Code)
	}
}
