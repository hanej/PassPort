package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/web"
	"github.com/yuin/goldmark"
	goldmarkhtml "github.com/yuin/goldmark/renderer/html"
)

// Renderer manages template parsing and rendering for the application.
type Renderer struct {
	pages    map[string]*template.Template
	logger   *slog.Logger
	branding atomic.Pointer[db.BrandingConfig]
	md       goldmark.Markdown
}

// PageData holds all data passed to templates for rendering.
type PageData struct {
	Title     string
	Session   *db.Session
	Flash     map[string]string
	CSRFField template.HTML
	CSRFToken string
	Data      any
}

// NewRenderer parses all templates from the embedded filesystem and returns
// a ready-to-use Renderer. Each page gets its own complete template set
// (layouts + partials + page) so that block overrides work correctly.
func NewRenderer(logger *slog.Logger) (*Renderer, error) {
	r := &Renderer{
		logger: logger,
		md:     goldmark.New(goldmark.WithRendererOptions(goldmarkhtml.WithUnsafe())),
	}

	// Set default branding so templates always have a value.
	r.branding.Store(&db.BrandingConfig{
		AppTitle:        "PassPort",
		AppAbbreviation: "PassPort",
		AppSubtitle:     "Self-Service Password Management",
	})

	funcMap := template.FuncMap{
		"branding": func() *db.BrandingConfig {
			return r.branding.Load()
		},
		"add": func(a, b int) int {
			return a + b
		},
		"subtract": func(a, b int) int {
			return a - b
		},
		"pages": func(totalPages int) []int {
			p := make([]int, totalPages)
			for i := range p {
				p[i] = i + 1
			}
			return p
		},
		// markdownHTML renders Markdown (including inline HTML for <u>, etc.) to
		// safe HTML. Input is admin-authored content, so raw HTML pass-through is
		// intentionally enabled.
		"markdownHTML": func(s string) template.HTML {
			var buf bytes.Buffer
			if err := r.md.Convert([]byte(s), &buf); err != nil {
				return template.HTML(template.HTMLEscapeString(s))
			}
			return template.HTML(buf.String())
		},
		"contains": strings.Contains,
		// fmtTime formats a time.Time (or *time.Time) in the local system timezone.
		// Use this in templates instead of bare {{.SomeTime}} or .Format to ensure
		// times are never shown in UTC. Logs and DB storage remain in UTC.
		"fmtTime": func(t any) string {
			switch v := t.(type) {
			case time.Time:
				return v.Local().Format("2006-01-02 15:04:05")
			case *time.Time:
				if v == nil {
					return ""
				}
				return v.Local().Format("2006-01-02 15:04:05")
			default:
				return ""
			}
		},
		// hexToRGB converts "#rrggbb" to "r, g, b" for Bootstrap's --bs-primary-rgb.
		"hexToRGB": func(hex string) string {
			r, g, b, ok := parseHex(hex)
			if !ok {
				return ""
			}
			return fmt.Sprintf("%d, %d, %d", r, g, b)
		},
		// darkenHex darkens (positive frac) or lightens (negative frac) a "#rrggbb"
		// color by the given fraction. Returns the original value on bad input.
		"darkenHex": func(hex string, frac float64) string {
			r, g, b, ok := parseHex(hex)
			if !ok {
				return hex
			}
			adjust := func(c int) int {
				v := math.Round(float64(c) * (1 - frac))
				return int(math.Max(0, math.Min(255, v)))
			}
			return fmt.Sprintf("#%02x%02x%02x", adjust(r), adjust(g), adjust(b))
		},
	}

	// Collect all template files from the embedded filesystem.
	var sharedFiles, pageFiles []string

	err := fs.WalkDir(web.Assets, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch {
		case matchDir(path, "templates/layouts/"):
			sharedFiles = append(sharedFiles, path)
		case matchDir(path, "templates/partials/"):
			sharedFiles = append(sharedFiles, path)
		case matchDir(path, "templates/pages/"):
			pageFiles = append(pageFiles, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking template directory: %w", err)
	}

	// Read shared file contents once.
	sharedContents := make([]string, len(sharedFiles))
	for i, f := range sharedFiles {
		data, err := fs.ReadFile(web.Assets, f)
		if err != nil {
			return nil, fmt.Errorf("reading template %s: %w", f, err)
		}
		sharedContents[i] = string(data)
	}

	// For each page, create a fresh template set: shared + page.
	// This ensures each page's {{define "content"}} block is registered
	// in the same template set as {{define "base"}}, so block resolution works.
	pages := make(map[string]*template.Template, len(pageFiles))

	for _, pf := range pageFiles {
		name := pageName(pf)

		t := template.New(name).Funcs(funcMap)

		// Parse shared templates (layouts + partials) into this set.
		for i, content := range sharedContents {
			if _, err := t.Parse(content); err != nil {
				return nil, fmt.Errorf("parsing shared template %s for page %s: %w", sharedFiles[i], name, err)
			}
		}

		// Parse the page template into the same set.
		pageData, err := fs.ReadFile(web.Assets, pf)
		if err != nil {
			return nil, fmt.Errorf("reading page template %s: %w", pf, err)
		}
		if _, err := t.Parse(string(pageData)); err != nil {
			return nil, fmt.Errorf("parsing page template %s: %w", pf, err)
		}

		pages[name] = t
	}

	logger.Info("templates loaded",
		"shared", len(sharedFiles),
		"pages", len(pageFiles),
	)

	r.pages = pages
	return r, nil
}

// Render executes the named page template with the given PageData and writes
// the result to the response writer. The template name should be the page
// filename without the directory prefix (e.g., "login.html").
func (r *Renderer) Render(w http.ResponseWriter, _ *http.Request, tmpl string, data PageData) {
	t, ok := r.pages[tmpl]
	if !ok {
		r.logger.Error("template not found", "template", tmpl)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Render to a buffer first so partial writes don't send broken HTML.
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "base", data); err != nil {
		r.logger.Error("template execution failed", "template", tmpl, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// RenderError renders the error page with the given HTTP status code and
// human-readable message.
func (r *Renderer) RenderError(w http.ResponseWriter, req *http.Request, code int, message string) {
	w.WriteHeader(code)
	r.Render(w, req, "error.html", PageData{
		Title: fmt.Sprintf("Error %d", code),
		Data: map[string]any{
			"ErrorCode":    code,
			"ErrorMessage": message,
		},
	})
}

// JSON writes a JSON response with the given HTTP status code.
func (r *Renderer) JSON(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		r.logger.Error("json encoding failed", "error", err)
	}
}

// SetBranding updates the branding configuration used by all templates.
// This is safe to call concurrently from any goroutine.
func (r *Renderer) SetBranding(cfg *db.BrandingConfig) {
	r.branding.Store(cfg)
}

// matchDir checks whether a path starts with the given directory prefix.
func matchDir(path, prefix string) bool {
	return len(path) > len(prefix) && path[:len(prefix)] == prefix
}

// parseHex parses a "#rrggbb" hex color into its R, G, B components.
func parseHex(hex string) (r, g, b int, ok bool) {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) != 6 {
		return
	}
	v, err := strconv.ParseUint(hex, 16, 32)
	if err != nil {
		return
	}
	return int(v >> 16), int((v >> 8) & 0xff), int(v & 0xff), true
}

// pageName extracts the filename from a template path like
// "templates/pages/login.html" and returns "login.html".
func pageName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}
