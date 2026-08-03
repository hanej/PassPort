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
	"github.com/hanej/passport/internal/crypto"
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
	crypto   *crypto.Service
}

func NewADChangePasswordHandler(
	sessions *auth.SessionManager,
	renderer *Renderer,
	auditLog *audit.Logger,
	logger *slog.Logger,
	registry *idp.Registry,
	store db.Store,
	cryptoSvc *crypto.Service,
) *ADChangePasswordHandler {
	return &ADChangePasswordHandler{
		sessions: sessions,
		renderer: renderer,
		audit:    auditLog,
		logger:   logger,
		registry: registry,
		store:    store,
		crypto:   cryptoSvc,
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

// pageData builds the render data for the change form, including the directory's
// password rules when they can be read. The directory stays the authority, so a
// failure here just omits the client-side rules.
func (h *ADChangePasswordHandler) pageData(r *http.Request, sess *db.Session) map[string]any {
	data := map[string]any{"ComplexityHint": ""}
	if sess == nil {
		return data
	}
	data["ComplexityHint"] = h.loadComplexityHint(r, sess.ProviderID)

	provider, ok := h.registry.Get(sess.ProviderID)
	if !ok {
		return data
	}
	reader, ok := provider.(idp.PasswordPolicyReader)
	if !ok {
		return data
	}
	if dirPolicy, err := reader.ResolvePasswordPolicy(r.Context(), sess.Username); err == nil {
		data["PasswordPolicy"] = dirPolicy
	} else {
		h.logger.Warn("could not read password policy for display",
			"username", sess.Username, "error", err)
	}
	return data
}

// ShowChangePassword renders the AD change password form.
func (h *ADChangePasswordHandler) ShowChangePassword(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	h.renderer.Render(w, r, "ad_force_password_change.html", PageData{
		Title:   "Change Password",
		Session: sess,
		Data:    h.pageData(r, sess),
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
			Data:    h.pageData(r, sess),
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
			msg = "The new password does not meet your organization's complexity, history, or minimum age requirements."
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

	// Best-effort notification email. Failure here must not affect the
	// already-successful password change.
	providerName := sess.ProviderID
	if idpRecord, idpErr := h.store.GetIDP(r.Context(), sess.ProviderID); idpErr == nil && idpRecord != nil {
		providerName = idpRecord.FriendlyName
	}
	userEmail, emailErr := resolveNotificationEmailByUsername(r.Context(), h.store, h.registry, sess.ProviderID, sess.Username)
	if emailErr != nil {
		h.logger.Warn("could not resolve notification email address",
			"idp_id", sess.ProviderID, "username", sess.Username, "error", emailErr)
	}
	sendPasswordEventEmail(r.Context(), h.store, h.crypto, h.logger,
		"password_changed", sess.ProviderID, providerName, sess.Username, userEmail, r.RemoteAddr)

	h.sessions.SetFlash(w, r, "success", "Password changed successfully.")
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}
