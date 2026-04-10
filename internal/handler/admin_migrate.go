package handler

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/migrate"
)

// AdminMigrateHandler handles export/import migration in the admin UI.
type AdminMigrateHandler struct {
	store      db.Store
	crypto     *crypto.Service
	renderer   *Renderer
	audit      *audit.Logger
	logger     *slog.Logger
	uploadsDir string
}

// NewAdminMigrateHandler creates a new AdminMigrateHandler.
func NewAdminMigrateHandler(
	store db.Store,
	cryptoSvc *crypto.Service,
	renderer *Renderer,
	auditLogger *audit.Logger,
	logger *slog.Logger,
	uploadsDir string,
) *AdminMigrateHandler {
	return &AdminMigrateHandler{
		store:      store,
		crypto:     cryptoSvc,
		renderer:   renderer,
		audit:      auditLogger,
		logger:     logger,
		uploadsDir: uploadsDir,
	}
}

// Show renders the migration page with Export and Import buttons.
// GET /admin/migrate
func (h *AdminMigrateHandler) Show(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	h.renderer.Render(w, r, "admin_migrate.html", PageData{
		Title:   "Import/Export",
		Session: sess,
		Data: map[string]any{
			"ActivePage": "migrate",
		},
	})
}

// Export builds the export and sends it as a ZIP download containing
// passport-export.json and all files from the uploads directory.
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

	// Build ZIP containing passport-export.json and uploads/*
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	jw, err := zw.Create("passport-export.json")
	if err != nil {
		h.logger.Error("export: failed to create zip entry for JSON", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to generate export archive")
		return
	}
	if _, err := jw.Write(jsonBytes); err != nil {
		h.logger.Error("export: failed to write JSON to zip", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to generate export archive")
		return
	}

	// Add upload files if the directory exists
	if h.uploadsDir != "" {
		_ = filepath.WalkDir(h.uploadsDir, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() {
				return nil
			}
			relPath, err := filepath.Rel(h.uploadsDir, path)
			if err != nil {
				return nil
			}
			entry, err := zw.Create("uploads/" + filepath.ToSlash(relPath))
			if err != nil {
				return nil
			}
			f, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer func() { _ = f.Close() }()
			_, _ = io.Copy(entry, f)
			return nil
		})
	}

	if err := zw.Close(); err != nil {
		h.logger.Error("export: failed to finalize zip", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to finalize export archive")
		return
	}

	h.audit.Log(ctx, &db.AuditEntry{
		Username: sess.Username,
		SourceIP: r.RemoteAddr,
		Action:   "config_exported",
		Result:   "success",
		Details:  fmt.Sprintf("Configuration exported: %d IDPs, %d admins, %d mappings", len(data.IdentityProviders), len(data.LocalAdmins), len(data.UserMappings)),
	})

	filename := fmt.Sprintf("passport-export-%s.zip", time.Now().Format("2006-01-02"))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// Import accepts a ZIP file upload containing passport-export.json (and optionally
// uploads/*), parses the JSON, validates, imports all selected data, and restores
// any upload files.
// POST /admin/migrate/import
func (h *AdminMigrateHandler) Import(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	ctx := r.Context()

	// Parse multipart form (max 50MB for zip with uploads).
	if err := r.ParseMultipartForm(50 << 20); err != nil {
		h.renderMigratePage(w, r, sess, "error", "Invalid form data: "+err.Error(), nil)
		return
	}

	file, _, err := r.FormFile("import_file")
	if err != nil {
		h.renderMigratePage(w, r, sess, "error", "Please select an export file to import.", nil)
		return
	}
	defer func() { _ = file.Close() }()

	// Read all ZIP bytes into memory so we can use zip.NewReader.
	zipBytes, err := io.ReadAll(file)
	if err != nil {
		h.renderMigratePage(w, r, sess, "error", "Failed to read uploaded file: "+err.Error(), nil)
		return
	}

	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		h.renderMigratePage(w, r, sess, "error", "Invalid ZIP file: "+err.Error(), nil)
		return
	}

	// Locate and decode passport-export.json from the ZIP.
	var data migrate.ExportData
	var jsonFound bool
	for _, zf := range zr.File {
		if zf.Name != "passport-export.json" {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			h.renderMigratePage(w, r, sess, "error", "Failed to open passport-export.json: "+err.Error(), nil)
			return
		}
		decoder := json.NewDecoder(rc)
		decoder.DisallowUnknownFields()
		decodeErr := decoder.Decode(&data)
		_ = rc.Close()
		if decodeErr != nil {
			h.renderMigratePage(w, r, sess, "error", "Invalid JSON format: "+decodeErr.Error(), nil)
			return
		}
		jsonFound = true
		break
	}

	if !jsonFound {
		h.renderMigratePage(w, r, sess, "error", "Archive does not contain passport-export.json.", nil)
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
		Uploads:   r.FormValue("import_uploads") == "1",
	}

	result, err := migrate.RunImport(ctx, h.store, h.crypto, &data, sections)
	if err != nil {
		h.renderMigratePage(w, r, sess, "error", "Import failed: "+err.Error(), nil)
		return
	}

	// Restore upload files from the ZIP (guarded against zip-slip attacks).
	if sections.Uploads && h.uploadsDir != "" {
		uploadsBase := filepath.Clean(h.uploadsDir) + string(os.PathSeparator)
		for _, zf := range zr.File {
			if !strings.HasPrefix(zf.Name, "uploads/") || zf.FileInfo().IsDir() {
				continue
			}
			relPath := strings.TrimPrefix(zf.Name, "uploads/")
			if relPath == "" {
				continue
			}
			dst := filepath.Join(h.uploadsDir, filepath.FromSlash(relPath))
			// Zip-slip protection: ensure the resolved path stays within uploadsDir.
			if !strings.HasPrefix(filepath.Clean(dst)+string(os.PathSeparator), uploadsBase) {
				h.logger.Warn("import: skipping unsafe zip entry", "name", zf.Name)
				continue
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0750); err != nil {
				continue
			}
			rc, err := zf.Open()
			if err != nil {
				continue
			}
			outFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
			if err != nil {
				_ = rc.Close()
				continue
			}
			_, _ = io.Copy(outFile, rc)
			_ = outFile.Close()
			_ = rc.Close()
			result.UploadFiles++
		}
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
		Details: fmt.Sprintf("Import: %d admins, %d IDPs, %d groups, %d mappings, SMTP=%v, %d MFA, branding=%v, %d templates, %d uploads, %d errors",
			result.LocalAdmins, result.IDPs, result.AdminGroups, result.UserMappings,
			result.SMTP, result.MFAProviders, result.Branding, result.EmailTemplates, result.UploadFiles, len(result.Errors)),
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
		Title:   "Import/Export",
		Session: sess,
		Flash:   map[string]string{"category": category, "message": message},
		Data: map[string]any{
			"ActivePage":   "migrate",
			"ImportResult": result,
		},
	})
}
