package handler

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	_ "image/gif"  // register GIF decoder for image.DecodeConfig
	_ "image/jpeg" // register JPEG decoder for image.DecodeConfig
	_ "image/png"  // register PNG decoder for image.DecodeConfig
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/email"
)

// maxEmailImageBytes caps a single image library upload.
const maxEmailImageBytes = 5 << 20

// emailImageExtByType maps the sniffed content type of an accepted upload to
// the extension used for its stored filename.
var emailImageExtByType = map[string]string{
	"image/png":  ".png",
	"image/jpeg": ".jpg",
	"image/gif":  ".gif",
}

// AdminEmailImagesHandler manages the image library used by email templates.
type AdminEmailImagesHandler struct {
	store    db.Store
	renderer *Renderer
	sessions *auth.SessionManager
	audit    *audit.Logger
	logger   *slog.Logger
	dir      string
}

// NewAdminEmailImagesHandler creates a new AdminEmailImagesHandler storing
// files in dir (typically <uploads>/email-images).
func NewAdminEmailImagesHandler(
	store db.Store,
	renderer *Renderer,
	sessions *auth.SessionManager,
	auditLogger *audit.Logger,
	logger *slog.Logger,
	dir string,
) *AdminEmailImagesHandler {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		logger.Error("failed to create email images directory", "path", dir, "error", err)
	}
	return &AdminEmailImagesHandler{
		store:    store,
		renderer: renderer,
		sessions: sessions,
		audit:    auditLogger,
		logger:   logger,
		dir:      dir,
	}
}

type emailImageRow struct {
	db.EmailImage
	URL       string
	SizeLabel string
	UsedBy    []string
}

// List renders the image library page.
// GET /admin/email-templates/images
func (h *AdminEmailImagesHandler) List(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	images, err := h.store.ListEmailImages(r.Context())
	if err != nil {
		h.logger.Error("failed to list email images", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to load image library")
		return
	}

	templates, err := h.store.ListEmailTemplates(r.Context())
	if err != nil {
		h.logger.Warn("failed to load templates for image usage", "error", err)
	}

	rows := make([]emailImageRow, 0, len(images))
	for _, img := range images {
		rows = append(rows, emailImageRow{
			EmailImage: img,
			URL:        email.InlineImagePathPrefix + img.Filename,
			SizeLabel:  formatImageSize(img.SizeBytes),
			UsedBy:     templatesUsingImage(templates, img.Filename),
		})
	}

	h.renderer.Render(w, r, "admin_email_images.html", PageData{
		Title:   "Email Image Library",
		Session: sess,
		Data: map[string]any{
			"Images":     rows,
			"MaxSizeMB":  maxEmailImageBytes >> 20,
			"ActivePage": "email_templates",
		},
	})
}

// Upload stores a new image in the library.
// POST /admin/email-templates/images
func (h *AdminEmailImagesHandler) Upload(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	// Leave headroom over the file limit for the multipart envelope and fields.
	r.Body = http.MaxBytesReader(w, r.Body, maxEmailImageBytes+(64<<10))
	if err := r.ParseMultipartForm(maxEmailImageBytes); err != nil {
		h.flashRedirect(w, r, "error", fmt.Sprintf("Upload failed: the image must be %d MB or smaller", maxEmailImageBytes>>20))
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	file, header, err := r.FormFile("image_file")
	if err != nil {
		h.flashRedirect(w, r, "error", "Choose an image to upload")
		return
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, maxEmailImageBytes+1))
	if err != nil {
		h.logger.Error("failed to read uploaded email image", "error", err)
		h.flashRedirect(w, r, "error", "Failed to read the uploaded image")
		return
	}
	if len(data) > maxEmailImageBytes {
		h.flashRedirect(w, r, "error", fmt.Sprintf("Upload failed: the image must be %d MB or smaller", maxEmailImageBytes>>20))
		return
	}

	contentType, ext, width, height, err := validateEmailImage(header.Filename, data)
	if err != nil {
		h.flashRedirect(w, r, "error", "Upload failed: "+err.Error())
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(header.Filename), filepath.Ext(header.Filename))
	}
	if len(name) > 200 {
		name = name[:200]
	}

	filename, err := randomImageFilename(ext)
	if err != nil {
		h.logger.Error("failed to generate email image filename", "error", err)
		h.flashRedirect(w, r, "error", "Failed to save the image")
		return
	}
	destPath := filepath.Join(h.dir, filename)

	if err := writeNewFile(destPath, data); err != nil {
		h.logger.Error("failed to write email image", "path", destPath, "error", err)
		h.flashRedirect(w, r, "error", "Failed to save the image")
		return
	}

	img := &db.EmailImage{
		Name:        name,
		Filename:    filename,
		ContentType: contentType,
		SizeBytes:   int64(len(data)),
		Width:       width,
		Height:      height,
	}
	if err := h.store.CreateEmailImage(r.Context(), img); err != nil {
		_ = os.Remove(destPath)
		h.logger.Error("failed to record email image", "error", err)
		h.flashRedirect(w, r, "error", "Failed to save the image")
		return
	}

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp: time.Now().UTC(),
		Username:  sess.Username,
		SourceIP:  r.RemoteAddr,
		Action:    audit.ActionEmailImageUpload,
		Result:    audit.ResultSuccess,
		Details:   fmt.Sprintf("Uploaded email image %q (%s, %d bytes)", name, filename, len(data)),
	})

	h.flashRedirect(w, r, "success", fmt.Sprintf("Image %q uploaded", name))
}

// Delete removes an image from the library unless a template still uses it.
// POST /admin/email-templates/images/{id}/delete
func (h *AdminEmailImagesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		h.flashRedirect(w, r, "error", "Image not found")
		return
	}

	img, err := h.store.GetEmailImage(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		h.flashRedirect(w, r, "error", "Image not found")
		return
	}
	if err != nil {
		h.logger.Error("failed to load email image", "id", id, "error", err)
		h.flashRedirect(w, r, "error", "Failed to delete the image")
		return
	}

	templates, err := h.store.ListEmailTemplates(r.Context())
	if err != nil {
		h.logger.Error("failed to check email image usage", "error", err)
		h.flashRedirect(w, r, "error", "Failed to delete the image")
		return
	}
	if usedBy := templatesUsingImage(templates, img.Filename); len(usedBy) > 0 {
		h.flashRedirect(w, r, "error", fmt.Sprintf(
			"%q is used by %s. Remove it from those templates before deleting it.",
			img.Name, strings.Join(usedBy, ", ")))
		return
	}

	if err := h.store.DeleteEmailImage(r.Context(), id); err != nil {
		h.logger.Error("failed to delete email image", "id", id, "error", err)
		h.flashRedirect(w, r, "error", "Failed to delete the image")
		return
	}
	if err := os.Remove(filepath.Join(h.dir, filepath.Base(img.Filename))); err != nil && !os.IsNotExist(err) {
		h.logger.Warn("failed to remove email image file", "filename", img.Filename, "error", err)
	}

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp: time.Now().UTC(),
		Username:  sess.Username,
		SourceIP:  r.RemoteAddr,
		Action:    audit.ActionEmailImageDelete,
		Result:    audit.ResultSuccess,
		Details:   fmt.Sprintf("Deleted email image %q (%s)", img.Name, img.Filename),
	})

	h.flashRedirect(w, r, "success", fmt.Sprintf("Image %q deleted", img.Name))
}

func (h *AdminEmailImagesHandler) flashRedirect(w http.ResponseWriter, r *http.Request, category, msg string) {
	h.sessions.SetFlash(w, r, category, msg)
	http.Redirect(w, r, "/admin/email-templates/images", http.StatusFound)
}

// validateEmailImage checks that an upload is a PNG, JPEG, or GIF by both
// extension and content, and returns its content type, stored extension, and
// dimensions.
func validateEmailImage(originalName string, data []byte) (contentType, ext string, width, height int, err error) {
	switch strings.ToLower(filepath.Ext(originalName)) {
	case ".png", ".jpg", ".jpeg", ".gif":
	default:
		return "", "", 0, 0, errors.New("invalid file type. Allowed: PNG, JPG, GIF")
	}

	contentType = http.DetectContentType(data)
	ext, ok := emailImageExtByType[contentType]
	if !ok {
		return "", "", 0, 0, errors.New("the file is not a valid PNG, JPG, or GIF image")
	}

	cfg, _, decErr := image.DecodeConfig(bytes.NewReader(data))
	if decErr != nil {
		return "", "", 0, 0, errors.New("the file is not a valid PNG, JPG, or GIF image")
	}
	return contentType, ext, cfg.Width, cfg.Height, nil
}

func formatImageSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func randomImageFilename(ext string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b) + ext, nil
}

func writeNewFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

// templatesUsingImage returns the friendly names of templates whose subject or
// body references the library image filename.
func templatesUsingImage(templates []db.EmailTemplate, filename string) []string {
	ref := email.InlineImagePathPrefix + filename
	var names []string
	for _, t := range templates {
		if strings.Contains(t.BodyHTML, ref) || strings.Contains(t.Subject, ref) {
			names = append(names, friendlyTemplateName(t.TemplateType))
		}
	}
	sort.Strings(names)
	return names
}
