package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/csrf"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
)

// ForgotPasswordHandler handles the self-service forgot-password flow.
// Users do not need to be logged in to initiate this flow. DUO MFA is used
// to verify identity before allowing the password reset when enabled.
type ForgotPasswordHandler struct {
	store    db.Store
	registry *idp.Registry
	sessions *auth.SessionManager
	renderer *Renderer
	audit    *audit.Logger
	logger   *slog.Logger
}

// NewForgotPasswordHandler creates a new ForgotPasswordHandler.
func NewForgotPasswordHandler(
	store db.Store,
	registry *idp.Registry,
	sessions *auth.SessionManager,
	renderer *Renderer,
	auditLogger *audit.Logger,
	logger *slog.Logger,
) *ForgotPasswordHandler {
	return &ForgotPasswordHandler{
		store:    store,
		registry: registry,
		sessions: sessions,
		renderer: renderer,
		audit:    auditLogger,
		logger:   logger,
	}
}

// ShowForm renders the forgot-password form with a list of enabled IDPs.
// GET /forgot-password
func (h *ForgotPasswordHandler) ShowForm(w http.ResponseWriter, r *http.Request) {
	idps, err := h.store.ListEnabledIDPs(r.Context())
	if err != nil {
		h.logger.Error("failed to list enabled IDPs", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}

	flash := h.sessions.GetFlash(r)

	h.renderer.Render(w, r, "forgot_password.html", PageData{
		Title:     "Forgot Password",
		CSRFField: csrf.TemplateField(r),
		Flash:     flash,
		Data: map[string]any{
			"IDPs": idps,
		},
	})
}

// Submit validates the forgot-password form, verifies the user exists in the
// directory, creates a temporary reset session, and redirects to the MFA flow
// (if enabled) or directly to the reset-password page.
// POST /forgot-password
func (h *ForgotPasswordHandler) Submit(w http.ResponseWriter, r *http.Request) {
	idpID := strings.TrimSpace(r.FormValue("idp_id"))
	username := strings.TrimSpace(r.FormValue("username"))

	if idpID == "" || username == "" {
		h.renderFormError(w, r, "Please select an identity provider and enter your username.")
		return
	}

	// Local admin accounts cannot use forgot-password.
	if idpID == "local" {
		h.renderFormError(w, r, "Password reset is not available for local admin accounts.")
		return
	}

	provider, ok := h.registry.Get(idpID)
	if !ok {
		h.renderFormError(w, r, "Identity provider not available.")
		return
	}

	// Verify the user exists in the directory. Try uid first, then sAMAccountName.
	_, err := provider.SearchUser(r.Context(), "uid", username)
	if err != nil {
		_, err = provider.SearchUser(r.Context(), "sAMAccountName", username)
	}
	if err != nil {
		h.logger.Debug("forgot-password user lookup failed",
			"idp_id", idpID,
			"username", username,
			"error", err,
		)
		h.audit.Log(r.Context(), &db.AuditEntry{
			Timestamp:  time.Now().UTC(),
			Username:   username,
			SourceIP:   r.RemoteAddr,
			Action:     audit.ActionPasswordReset,
			ProviderID: idpID,
			Result:     audit.ResultFailure,
			Details:    "User not found in directory",
		})
		h.renderFormError(w, r, "User not found. Please check your username and try again.")
		return
	}

	// Create a temporary session with user_type="reset".
	sessionID, err := h.sessions.CreateSession(w, r, "reset", idpID, username, false, false)
	if err != nil {
		h.logger.Error("failed to create reset session", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}

	h.logger.Info("forgot-password session created",
		"session_id", sessionID,
		"username", username,
		"idp_id", idpID,
	)

	// Check whether MFA is configured for this IDP.
	mfaProvider, err := h.store.GetMFAProviderForIDP(r.Context(), idpID)
	if err != nil {
		h.logger.Error("failed to check MFA provider for IDP", "idp_id", idpID, "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}
	if mfaProvider != nil {
		// MFA is enabled — redirect to MFA verification.
		http.Redirect(w, r, "/mfa", http.StatusFound)
		return
	}

	// No MFA — go directly to reset-password.
	http.Redirect(w, r, "/reset-password", http.StatusFound)
}

// ShowReset renders the new-password form. The user must have a valid reset
// session and, if MFA is enabled, must have completed MFA verification.
// The actual admin reset and password change happen atomically in the POST handler.
// GET /reset-password
func (h *ForgotPasswordHandler) ShowReset(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil || sess.UserType != "reset" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// If MFA is configured for this IDP, verify it was completed.
	mfaProvider, err := h.store.GetMFAProviderForIDP(r.Context(), sess.ProviderID)
	if err != nil {
		h.logger.Error("failed to check MFA provider", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}
	if mfaProvider != nil && sess.MFAState != "verified" {
		h.logger.Warn("reset-password accessed without MFA verification", "username", sess.Username)
		h.sessions.SetFlash(w, r, "error", "MFA verification is required before resetting your password.")
		http.Redirect(w, r, "/forgot-password", http.StatusFound)
		return
	}

	// Look up the IDP friendly name and complexity hint for display.
	idpRecord, _ := h.store.GetIDP(r.Context(), sess.ProviderID)
	idpName := sess.ProviderID
	if idpRecord != nil {
		idpName = idpRecord.FriendlyName
	}

	var complexityHint string
	if idpRecord != nil && idpRecord.ConfigJSON != "" {
		var cfg idp.Config
		if err := json.Unmarshal([]byte(idpRecord.ConfigJSON), &cfg); err == nil {
			complexityHint = cfg.PasswordComplexityHint
		}
	}

	flash := h.sessions.GetFlash(r)

	h.renderer.Render(w, r, "reset_password.html", PageData{
		Title:     "Reset Password",
		CSRFField: csrf.TemplateField(r),
		Flash:     flash,
		Data: map[string]any{
			"Username":       sess.Username,
			"IDPName":        idpName,
			"ComplexityHint": complexityHint,
		},
	})
}

// ResetPassword processes the password reset form. It resolves the user DN,
// generates a temporary password, admin-resets the IDP account to it, then
// immediately calls provider.ChangePassword (user-bind) so the directory
// enforces its full password policy (complexity, history, minimum age).
// Logs the event, destroys the session, and redirects to login with a success message.
// POST /reset-password
func (h *ForgotPasswordHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil || sess.UserType != "reset" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// If MFA is configured for this IDP, verify it was completed.
	mfaProvider, err := h.store.GetMFAProviderForIDP(r.Context(), sess.ProviderID)
	if err != nil {
		h.logger.Error("failed to check MFA provider", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}
	if mfaProvider != nil && sess.MFAState != "verified" {
		http.Redirect(w, r, "/forgot-password", http.StatusFound)
		return
	}

	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	if newPassword == "" {
		h.sessions.SetFlash(w, r, "error", "New password cannot be empty.")
		http.Redirect(w, r, "/reset-password", http.StatusFound)
		return
	}

	if newPassword != confirmPassword {
		h.sessions.SetFlash(w, r, "error", "Passwords do not match.")
		http.Redirect(w, r, "/reset-password", http.StatusFound)
		return
	}

	provider, ok := h.registry.Get(sess.ProviderID)
	if !ok {
		h.logger.Error("provider not found during password reset", "provider_id", sess.ProviderID)
		h.sessions.SetFlash(w, r, "error", "Identity provider not available.")
		http.Redirect(w, r, "/reset-password", http.StatusFound)
		return
	}

	// Resolve the user DN from the username.
	userDN, err := provider.SearchUser(r.Context(), "uid", sess.Username)
	if err != nil {
		userDN, err = provider.SearchUser(r.Context(), "sAMAccountName", sess.Username)
	}
	if err != nil {
		h.logger.Error("failed to resolve user DN for reset",
			"username", sess.Username,
			"error", err,
		)
		h.audit.Log(r.Context(), &db.AuditEntry{
			Timestamp:  time.Now().UTC(),
			Username:   sess.Username,
			SourceIP:   r.RemoteAddr,
			Action:     audit.ActionPasswordReset,
			ProviderID: sess.ProviderID,
			Result:     audit.ResultFailure,
			Details:    fmt.Sprintf("Failed to resolve user DN: %v", err),
		})
		h.sessions.SetFlash(w, r, "error", "Unable to locate your account. Please try again.")
		http.Redirect(w, r, "/reset-password", http.StatusFound)
		return
	}

	// Load IDP password policy for temp password generation.
	pwLen, pwUpper, pwLower, pwDigits, pwSpecial := 16, true, true, true, "!@#$%^&()"
	if idpRecord, recErr := h.store.GetIDP(r.Context(), sess.ProviderID); recErr == nil && idpRecord.ConfigJSON != "" {
		var cfg idp.Config
		if jsonErr := json.Unmarshal([]byte(idpRecord.ConfigJSON), &cfg); jsonErr == nil && cfg.PasswordLength > 0 {
			pwLen = cfg.PasswordLength
			pwUpper = cfg.PasswordAllowUppercase
			pwLower = cfg.PasswordAllowLowercase
			pwDigits = cfg.PasswordAllowDigits
			if cfg.PasswordAllowSpecialChars {
				pwSpecial = cfg.PasswordSpecialChars
			} else {
				pwSpecial = ""
			}
		}
	}

	// Generate a temporary password and admin-reset the account to it.
	// Then immediately use ChangePassword (user-bind) so that the directory
	// enforces its full password policy (history, complexity, minimum age).
	tempPass, err := auth.GeneratePasswordWithPolicy(pwLen, pwUpper, pwLower, pwDigits, pwSpecial)
	if err != nil {
		h.logger.Error("failed to generate temp password", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}

	if err := provider.ResetPassword(r.Context(), userDN, tempPass); err != nil {
		h.logger.Error("admin reset failed during password reset flow",
			"username", sess.Username, "error", err)
		h.audit.Log(r.Context(), &db.AuditEntry{
			Timestamp:  time.Now().UTC(),
			Username:   sess.Username,
			SourceIP:   r.RemoteAddr,
			Action:     audit.ActionPasswordReset,
			ProviderID: sess.ProviderID,
			Result:     audit.ResultFailure,
			Details:    fmt.Sprintf("Admin reset failed: %v", err),
		})
		h.sessions.SetFlash(w, r, "error", "Failed to initiate password reset. Please try again.")
		http.Redirect(w, r, "/reset-password", http.StatusFound)
		return
	}

	if err := provider.ChangePassword(r.Context(), userDN, tempPass, newPassword); err != nil {
		h.logger.Error("password reset failed",
			"username", sess.Username,
			"error", err,
		)
		h.audit.Log(r.Context(), &db.AuditEntry{
			Timestamp:  time.Now().UTC(),
			Username:   sess.Username,
			SourceIP:   r.RemoteAddr,
			Action:     audit.ActionPasswordReset,
			ProviderID: sess.ProviderID,
			Result:     audit.ResultFailure,
			Details:    fmt.Sprintf("Password reset failed: %v", err),
		})
		errMsg := sanitizeDN(err.Error(), userDN, sess.Username)
		h.sessions.SetFlash(w, r, "error", "Password reset failed: "+errMsg)
		http.Redirect(w, r, "/reset-password", http.StatusFound)
		return
	}

	h.logger.Info("password reset successful",
		"username", sess.Username,
		"provider_id", sess.ProviderID,
	)

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp:  time.Now().UTC(),
		Username:   sess.Username,
		SourceIP:   r.RemoteAddr,
		Action:     audit.ActionPasswordReset,
		ProviderID: sess.ProviderID,
		Result:     audit.ResultSuccess,
		Details:    "Password reset via forgot-password flow",
	})

	// Destroy the reset session.
	h.sessions.DestroySession(w, r)

	// We need a new temporary session to hold the flash message since
	// DestroySession cleared the cookie. Create a short-lived one.
	_, err = h.sessions.CreateSession(w, r, "flash", "", "", false, false)
	if err != nil {
		// Even if we can't set the flash, the reset succeeded.
		h.logger.Warn("failed to create flash session after reset", "error", err)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	h.sessions.SetFlash(w, r, "success", "Password reset successfully. You may now log in with your new password.")
	http.Redirect(w, r, "/login", http.StatusFound)
}

// renderFormError re-renders the forgot-password form with an error message.
func (h *ForgotPasswordHandler) renderFormError(w http.ResponseWriter, r *http.Request, message string) {
	idps, err := h.store.ListEnabledIDPs(r.Context())
	if err != nil {
		h.logger.Error("failed to list enabled IDPs", "error", err)
	}

	h.renderer.Render(w, r, "forgot_password.html", PageData{
		Title:     "Forgot Password",
		CSRFField: csrf.TemplateField(r),
		Flash:     map[string]string{"category": "error", "message": message},
		Data: map[string]any{
			"IDPs": idps,
		},
	})
}
