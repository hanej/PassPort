package handler

import (
	"bytes"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/gorilla/csrf"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer/html"

	"github.com/hanej/passport/internal/auth"
)

// AdminDocsHandler serves the embedded documentation in the admin UI.
type AdminDocsHandler struct {
	renderer    *Renderer
	logger      *slog.Logger
	renderedDoc template.HTML // cached HTML output
}

// NewAdminDocsHandler creates a new AdminDocsHandler, rendering the markdown once at startup.
// docContent is the raw markdown bytes (embedded by the caller).
func NewAdminDocsHandler(renderer *Renderer, logger *slog.Logger, docContent []byte) *AdminDocsHandler {
	md := goldmark.New(
		goldmark.WithExtensions(extension.GFM, extension.Table),
		goldmark.WithParserOptions(parser.WithAutoHeadingID()),
		goldmark.WithRendererOptions(html.WithUnsafe()),
	)

	var buf bytes.Buffer
	if err := md.Convert(docContent, &buf); err != nil {
		logger.Error("failed to render documentation markdown", "error", err)
	}

	return &AdminDocsHandler{
		renderer:    renderer,
		logger:      logger,
		renderedDoc: template.HTML(buf.String()),
	}
}

// Show renders the documentation page.
// GET /admin/docs
func (h *AdminDocsHandler) Show(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	h.renderer.Render(w, r, "admin_docs.html", PageData{
		Title:     "Documentation",
		Session:   sess,
		CSRFField: csrf.TemplateField(r),
		Data: map[string]any{
			"Content":    h.renderedDoc,
			"ActivePage": "docs",
		},
	})
}
