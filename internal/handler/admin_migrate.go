package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/csrf"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/migrate"
)

// AdminMigrateHandler handles export/import migration in the admin UI.
type AdminMigrateHandler struct {
	store    db.Store
	crypto   *crypto.Service
	renderer *Renderer
	audit    *audit.Logger
	logger   *slog.Logger
}

// NewAdminMigrateHandler creates a new AdminMigrateHandler.
func NewAdminMigrateHandler(
	store db.Store,
	cryptoSvc *crypto.Service,
	renderer *Renderer,
	auditLogger *audit.Logger,
	logger *slog.Logger,
) *AdminMigrateHandler {
	return &AdminMigrateHandler{
		store:    store,
		crypto:   cryptoSvc,
		renderer: renderer,
		audit:    auditLogger,
		logger:   logger,
	}
}

// Show renders the migration page with Export and Import buttons.
// GET /admin/migrate
func (h *AdminMigrateHandler) Show(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	h.renderer.Render(w, r, "admin_migrate.html", PageData{
		Title:     "Import/Export",
		Session:   sess,
		CSRFField: csrf.TemplateField(r),
		Data: map[string]any{
			"ActivePage": "migrate",
		},
	})
}

// Export builds the JSON export and sends it as a download.
// GET /admin/migrate/export
func (h *AdminMigrateHandler) Export(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	ctx := r.Context()

	data, err := migrate.BuildExport(ctx, h.store, h.crypto)
	if err != nil {
		h.logger.Error("export: failed to build export", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to export: "+err.Error())
		return
	}

	// Marshal to JSON
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		h.logger.Error("export: failed to marshal JSON", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to generate export file")
		return
	}

	h.audit.Log(ctx, &db.AuditEntry{
		Username: sess.Username,
		SourceIP: r.RemoteAddr,
		Action:   "config_exported",
		Result:   "success",
		Details:  fmt.Sprintf("Configuration exported: %d IDPs, %d admins, %d mappings", len(data.IdentityProviders), len(data.LocalAdmins), len(data.UserMappings)),
	})

	filename := fmt.Sprintf("passport-export-%s.json", time.Now().Format("2006-01-02"))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(jsonBytes)
}

// Import accepts a file upload, parses the JSON, validates, and imports all data.
// POST /admin/migrate/import
func (h *AdminMigrateHandler) Import(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	ctx := r.Context()

	// Parse multipart form (max 10MB).
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		h.renderMigratePage(w, r, sess, "error", "Invalid form data: "+err.Error(), nil)
		return
	}

	file, _, err := r.FormFile("import_file")
	if err != nil {
		h.renderMigratePage(w, r, sess, "error", "Please select an export file to import.", nil)
		return
	}
	defer file.Close()

	var data migrate.ExportData
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&data); err != nil {
		h.renderMigratePage(w, r, sess, "error", "Invalid JSON format: "+err.Error(), nil)
		return
	}

	// Read selected sections from checkboxes.
	sections := migrate.ImportSections{
		Admins:    r.FormValue("import_admins") == "1",
		IDPs:      r.FormValue("import_idps") == "1",
		Groups:    r.FormValue("import_groups") == "1",
		Mappings:  r.FormValue("import_mappings") == "1",
		SMTP:      r.FormValue("import_smtp") == "1",
		MFA:       r.FormValue("import_mfa") == "1",
		Branding:  r.FormValue("import_branding") == "1",
		Templates: r.FormValue("import_templates") == "1",
	}

	result, err := migrate.RunImport(ctx, h.store, h.crypto, &data, sections)
	if err != nil {
		h.renderMigratePage(w, r, sess, "error", "Import failed: "+err.Error(), nil)
		return
	}

	// If branding was imported, update the renderer.
	if result.Branding && data.Branding != nil {
		h.renderer.SetBranding(data.Branding)
	}

	// Build summary message.
	category := "success"
	if len(result.Errors) > 0 {
		category = "warning"
	}

	h.audit.Log(ctx, &db.AuditEntry{
		Username: sess.Username,
		SourceIP: r.RemoteAddr,
		Action:   "config_imported",
		Result:   category,
		Details: fmt.Sprintf("Import: %d admins, %d IDPs, %d groups, %d mappings, SMTP=%v, %d MFA, branding=%v, %d templates, %d errors",
			result.LocalAdmins, result.IDPs, result.AdminGroups, result.UserMappings,
			result.SMTP, result.MFAProviders, result.Branding, result.EmailTemplates, len(result.Errors)),
	})

	h.logger.Info("configuration imported",
		"admin", sess.Username,
		"idps", result.IDPs,
		"admins", result.LocalAdmins,
		"errors", len(result.Errors),
	)

	h.renderMigratePage(w, r, sess, category, "Import completed successfully.", result)
}

func (h *AdminMigrateHandler) renderMigratePage(w http.ResponseWriter, r *http.Request, sess *db.Session, category, message string, result *migrate.ImportResult) {
	h.renderer.Render(w, r, "admin_migrate.html", PageData{
		Title:     "Import/Export",
		Session:   sess,
		Flash:     map[string]string{"category": category, "message": message},
		CSRFField: csrf.TemplateField(r),
		Data: map[string]any{
			"ActivePage":   "migrate",
			"ImportResult": result,
		},
	})
}
