package handler

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/csrf"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/db"
)

// BootstrapHandler serves the forced password change flow for local admin first login.
type BootstrapHandler struct {
	store    db.AdminStore
	sessions *auth.SessionManager
	renderer *Renderer
	audit    *audit.Logger
	logger   *slog.Logger
}

// NewBootstrapHandler creates a new BootstrapHandler.
func NewBootstrapHandler(
	store db.AdminStore,
	sessions *auth.SessionManager,
	renderer *Renderer,
	auditLogger *audit.Logger,
	logger *slog.Logger,
) *BootstrapHandler {
	return &BootstrapHandler{
		store:    store,
		sessions: sessions,
		renderer: renderer,
		audit:    auditLogger,
		logger:   logger,
	}
}

// ShowChangePassword renders the forced password change form.
// GET /change-password
func (h *BootstrapHandler) ShowChangePassword(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("ShowChangePassword called")

	sess := auth.SessionFromContext(r.Context())
	h.renderer.Render(w, r, "force_password_change.html", PageData{
		Title:     "Change Password",
		Session:   sess,
		CSRFField: csrf.TemplateField(r),
	})
}

// ChangePassword processes the forced password change form.
// POST /change-password
func (h *BootstrapHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	h.logger.Debug("ChangePassword called",
		"username", sess.Username,
	)

	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	if newPassword == "" {
		h.renderer.Render(w, r, "force_password_change.html", PageData{
			Title:     "Change Password",
			Session:   sess,
			CSRFField: csrf.TemplateField(r),
			Flash:     map[string]string{"category": "error", "message": "Password cannot be empty"},
		})
		return
	}

	if newPassword != confirmPassword {
		h.renderer.Render(w, r, "force_password_change.html", PageData{
			Title:     "Change Password",
			Session:   sess,
			CSRFField: csrf.TemplateField(r),
			Flash:     map[string]string{"category": "error", "message": "Passwords do not match"},
		})
		return
	}

	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		h.logger.Error("failed to hash password", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}

	if err := h.store.UpdateLocalAdminPassword(r.Context(), sess.Username, hash, false); err != nil {
		h.logger.Error("failed to update admin password", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}

	// Clear the must_change_password flag on the session.
	if err := h.sessions.UpdateSessionMustChangePassword(r.Context(), sess.ID, false); err != nil {
		h.logger.Error("failed to update session must_change_password", "error", err)
	}

	h.logger.Debug("bootstrap password changed successfully",
		"username", sess.Username,
	)

	// Set flash message.
	h.sessions.SetFlash(w, r, "success", "Password changed successfully")

	// Audit the event.
	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp: time.Now().UTC(),
		Username:  sess.Username,
		SourceIP:  r.RemoteAddr,
		Action:    audit.ActionAdminPasswordChange,
		Result:    audit.ResultSuccess,
		Details:   "Forced password change completed",
	})

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}
