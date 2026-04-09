package handler

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gorilla/csrf"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/db"
)

// AdminBrandingHandler handles branding configuration in the admin UI.
type AdminBrandingHandler struct {
	store      db.Store
	renderer   *Renderer
	audit      *audit.Logger
	logger     *slog.Logger
	uploadsDir string // directory for uploaded files
}

// NewAdminBrandingHandler creates a new AdminBrandingHandler.
func NewAdminBrandingHandler(
	store db.Store,
	renderer *Renderer,
	auditLogger *audit.Logger,
	logger *slog.Logger,
	uploadsDir string,
) *AdminBrandingHandler {
	// Ensure uploads directory exists.
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		logger.Error("failed to create uploads directory", "path", uploadsDir, "error", err)
	}
	return &AdminBrandingHandler{
		store:      store,
		renderer:   renderer,
		audit:      auditLogger,
		logger:     logger,
		uploadsDir: uploadsDir,
	}
}

// Show renders the branding configuration form.
// GET /admin/branding
func (h *AdminBrandingHandler) Show(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	cfg, err := h.store.GetBrandingConfig(r.Context())
	if err != nil {
		h.logger.Error("failed to load branding config", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to load branding configuration")
		return
	}

	h.renderer.Render(w, r, "admin_branding.html", PageData{
		Title:     "Branding",
		Session:   sess,
		CSRFField: csrf.TemplateField(r),
		Data: map[string]any{
			"Config":     cfg,
			"ActivePage": "branding",
		},
	})
}

// Save processes the branding configuration form with optional logo file upload.
// POST /admin/branding
func (h *AdminBrandingHandler) Save(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	// Parse multipart form (max 5MB for logo upload).
	if err := r.ParseMultipartForm(5 << 20); err != nil {
		h.renderer.RenderError(w, r, http.StatusBadRequest, "Invalid form data")
		return
	}

	// Load current config to preserve logo if no new file uploaded.
	currentCfg, _ := h.store.GetBrandingConfig(r.Context())
	logoURL := ""
	if currentCfg != nil {
		logoURL = currentCfg.LogoURL
	}

	// Handle logo file upload.
	file, header, err := r.FormFile("logo_file")
	if err == nil {
		defer func() { _ = file.Close() }()

		// Validate file type.
		ext := strings.ToLower(filepath.Ext(header.Filename))
		if ext != ".png" && ext != ".jpg" && ext != ".jpeg" && ext != ".svg" && ext != ".gif" && ext != ".webp" && ext != ".ico" {
			h.renderBrandingError(w, r, sess, "Invalid file type. Allowed: PNG, JPG, SVG, GIF, WebP, ICO")
			return
		}

		// Save file as "logo" + original extension.
		destName := "logo" + ext
		destPath := filepath.Join(h.uploadsDir, destName)

		out, err := os.Create(destPath)
		if err != nil {
			h.logger.Error("failed to create logo file", "path", destPath, "error", err)
			h.renderBrandingError(w, r, sess, "Failed to save logo file")
			return
		}
		defer func() { _ = out.Close() }()

		if _, err := io.Copy(out, file); err != nil {
			h.logger.Error("failed to write logo file", "path", destPath, "error", err)
			h.renderBrandingError(w, r, sess, "Failed to save logo file")
			return
		}

		logoURL = "/uploads/" + destName
		h.logger.Debug("logo uploaded", "path", destPath, "url", logoURL)
	}

	// Check if logo should be removed.
	if r.FormValue("remove_logo") == "1" {
		// Delete the file if it exists.
		if logoURL != "" {
			oldFile := filepath.Join(h.uploadsDir, filepath.Base(logoURL))
			_ = os.Remove(oldFile)
		}
		logoURL = ""
	}

	primaryColor := strings.ToLower(strings.TrimSpace(r.FormValue("primary_color")))
	primaryLightColor := strings.ToLower(strings.TrimSpace(r.FormValue("primary_light_color")))
	if primaryColor != "" && !validHexColor.MatchString(primaryColor) {
		h.renderBrandingError(w, r, sess, "Invalid primary color. Use a hex value like #2c5282.")
		return
	}
	if primaryLightColor != "" && !validHexColor.MatchString(primaryLightColor) {
		h.renderBrandingError(w, r, sess, "Invalid primary light color. Use a hex value like #3182ce.")
		return
	}

	cfg := &db.BrandingConfig{
		AppTitle:          strings.TrimSpace(r.FormValue("app_title")),
		AppAbbreviation:   strings.TrimSpace(r.FormValue("app_abbreviation")),
		AppSubtitle:       strings.TrimSpace(r.FormValue("app_subtitle")),
		LogoURL:           logoURL,
		FooterText:        strings.TrimSpace(r.FormValue("footer_text")),
		PrimaryColor:      primaryColor,
		PrimaryLightColor: primaryLightColor,
	}

	if cfg.AppTitle == "" {
		cfg.AppTitle = "PassPort"
	}
	if cfg.AppAbbreviation == "" {
		cfg.AppAbbreviation = "PassPort"
	}

	if err := h.store.SaveBrandingConfig(r.Context(), cfg); err != nil {
		h.logger.Error("failed to save branding config", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to save branding configuration")
		return
	}

	h.renderer.SetBranding(cfg)

	h.audit.Log(r.Context(), &db.AuditEntry{
		Username: sess.Username,
		SourceIP: r.RemoteAddr,
		Action:   "branding_updated",
		Result:   "success",
		Details:  fmt.Sprintf("Branding updated: title=%s, logo=%s", cfg.AppTitle, cfg.LogoURL),
	})

	h.logger.Info("branding config saved", "admin", sess.Username, "title", cfg.AppTitle, "logo", cfg.LogoURL)

	h.renderer.Render(w, r, "admin_branding.html", PageData{
		Title:     "Branding",
		Session:   sess,
		Flash:     map[string]string{"category": "success", "message": "Branding configuration saved successfully."},
		CSRFField: csrf.TemplateField(r),
		Data: map[string]any{
			"Config":     cfg,
			"ActivePage": "branding",
		},
	})
}

// validHexColor matches a CSS hex color like "#2c5282".
var validHexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

func (h *AdminBrandingHandler) renderBrandingError(w http.ResponseWriter, r *http.Request, sess *db.Session, msg string) {
	cfg, _ := h.store.GetBrandingConfig(r.Context())
	h.renderer.Render(w, r, "admin_branding.html", PageData{
		Title:     "Branding",
		Session:   sess,
		Flash:     map[string]string{"category": "error", "message": msg},
		CSRFField: csrf.TemplateField(r),
		Data: map[string]any{
			"Config":     cfg,
			"ActivePage": "branding",
		},
	})
}
