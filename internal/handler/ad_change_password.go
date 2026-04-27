package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
)

// ADChangePasswordHandler serves the forced password change flow for AD users.
type ADChangePasswordHandler struct {
	sessions *auth.SessionManager
	renderer *Renderer
	audit    *audit.Logger
	logger   *slog.Logger
	registry *idp.Registry
	store    db.Store
}

func NewADChangePasswordHandler(
	sessions *auth.SessionManager,
	renderer *Renderer,
	auditLog *audit.Logger,
	logger *slog.Logger,
	registry *idp.Registry,
	store db.Store,
) *ADChangePasswordHandler {
	return &ADChangePasswordHandler{
		sessions: sessions,
		renderer: renderer,
		audit:    auditLog,
		logger:   logger,
		registry: registry,
		store:    store,
	}
}

func (h *ADChangePasswordHandler) loadComplexityHint(r *http.Request, providerID string) string {
	record, err := h.store.GetIDP(r.Context(), providerID)
	if err != nil || record == nil || record.ConfigJSON == "" {
		return ""
	}
	var cfg idp.Config
	if err := json.Unmarshal([]byte(record.ConfigJSON), &cfg); err != nil {
		return ""
	}
	return cfg.PasswordComplexityHint
}

// ShowChangePassword renders the AD change password form.
func (h *ADChangePasswordHandler) ShowChangePassword(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	hint := ""
	if sess != nil {
		hint = h.loadComplexityHint(r, sess.ProviderID)
	}
	h.renderer.Render(w, r, "ad_force_password_change.html", PageData{
		Title:   "Change Password",
		Session: sess,
		Data:    map[string]any{"ComplexityHint": hint},
	})
}

// ChangePassword processes the forced password change form for AD users.
func (h *ADChangePasswordHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil || sess.ProviderID == "" {
		h.renderer.RenderError(w, r, http.StatusUnauthorized, "Session expired. Please log in again.")
		return
	}

	hint := h.loadComplexityHint(r, sess.ProviderID)

	renderForm := func(msg string) {
		h.renderer.Render(w, r, "ad_force_password_change.html", PageData{
			Title:   "Change Password",
			Session: sess,
			Flash:   map[string]string{"category": "error", "message": msg},
			Data:    map[string]any{"ComplexityHint": hint},
		})
	}

	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	if newPassword == "" {
		renderForm("New password cannot be empty.")
		return
	}
	if newPassword != confirmPassword {
		renderForm("Passwords do not match.")
		return
	}

	provider, ok := h.registry.Get(sess.ProviderID)
	if !ok {
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Identity provider not available.")
		return
	}

	err := provider.ChangePassword(r.Context(), sess.Username, currentPassword, newPassword)
	if err != nil {
		h.logger.Error("AD password change failed", "username", sess.Username, "error", err)

		var msg string
		switch {
		case errors.Is(err, idp.ErrPasswordPolicy):
			msg = "The new password does not meet your organization's requirements."
			if hint != "" {
				msg += " " + hint
			}
		case strings.Contains(err.Error(), "current password is incorrect"):
			msg = "Current password is incorrect."
		case errors.Is(err, idp.ErrAccountLocked):
			msg = "Your account is locked. Please contact your IT administrator."
		case errors.Is(err, idp.ErrAccountDisabled):
			msg = "Your account is disabled. Please contact your IT administrator."
		default:
			msg = "Password change failed. Please try again or contact your administrator."
		}

		renderForm(msg)
		return
	}

	if err := h.sessions.UpdateSessionMustChangePassword(r.Context(), sess.ID, false); err != nil {
		h.logger.Error("failed to clear must_change_password on session", "error", err)
	}

	h.logger.Info("AD password changed", "username", sess.Username)

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp: time.Now().UTC(),
		Username:  sess.Username,
		SourceIP:  r.RemoteAddr,
		Action:    audit.ActionPasswordChange,
		Result:    audit.ResultSuccess,
		Details:   "AD forced password change completed",
	})

	h.sessions.SetFlash(w, r, "success", "Password changed successfully.")
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}
