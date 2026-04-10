package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/email"
	"github.com/hanej/passport/internal/idp"
	"github.com/hanej/passport/internal/mfa"
	"github.com/hanej/passport/internal/mfa/duo"
	"github.com/hanej/passport/internal/mfa/emailotp"
)

// mfaMaxAttempts is the maximum number of failed OTP verification attempts
// allowed before the token is invalidated. The user must request a new code.
const mfaMaxAttempts = 3

// MFAHandler handles the MFA verification flow for password operations.
type MFAHandler struct {
	store    db.Store
	sessions *auth.SessionManager
	crypto   *crypto.Service
	registry *idp.Registry
	renderer *Renderer
	audit    *audit.Logger
	logger   *slog.Logger
}

// NewMFAHandler creates a new MFAHandler.
func NewMFAHandler(
	store db.Store,
	sessions *auth.SessionManager,
	cryptoSvc *crypto.Service,
	registry *idp.Registry,
	renderer *Renderer,
	auditLogger *audit.Logger,
	logger *slog.Logger,
) *MFAHandler {
	return &MFAHandler{
		store:    store,
		sessions: sessions,
		crypto:   cryptoSvc,
		registry: registry,
		renderer: renderer,
		audit:    auditLogger,
		logger:   logger,
	}
}

// buildMFAClientForIDP loads the effective MFA provider for an IDP and creates the appropriate client.
// Returns nil, nil, nil when no MFA provider is configured for the IDP.
// This is a package-level function so it can be shared by LoginHandler and MFAHandler.
func buildMFAClientForIDP(ctx context.Context, store db.Store, cryptoSvc *crypto.Service, idpID string, logger *slog.Logger) (mfa.Provider, *db.MFAProviderRecord, error) {
	record, err := store.GetMFAProviderForIDP(ctx, idpID)
	if err != nil {
		return nil, nil, fmt.Errorf("looking up MFA provider: %w", err)
	}
	if record == nil {
		return nil, nil, nil
	}

	switch mfa.ProviderType(record.ProviderType) {
	case mfa.ProviderTypeDuo:
		var duoConfig mfa.DuoConfig
		if err := json.Unmarshal([]byte(record.ConfigJSON), &duoConfig); err != nil {
			return nil, nil, fmt.Errorf("invalid DUO config: %w", err)
		}
		var duoSecrets mfa.DuoSecrets
		if len(record.SecretBlob) > 0 {
			plaintext, err := cryptoSvc.Decrypt(record.SecretBlob)
			if err != nil {
				return nil, nil, fmt.Errorf("decrypting DUO secrets: %w", err)
			}
			if err := json.Unmarshal(plaintext, &duoSecrets); err != nil {
				return nil, nil, fmt.Errorf("invalid DUO secrets: %w", err)
			}
		}
		client, err := duo.New(duoConfig, duoSecrets, logger)
		if err != nil {
			return nil, nil, fmt.Errorf("creating DUO client: %w", err)
		}
		return client, record, nil

	case mfa.ProviderTypeEmail:
		var cfg mfa.EmailOTPConfig
		if err := json.Unmarshal([]byte(record.ConfigJSON), &cfg); err != nil {
			return nil, nil, fmt.Errorf("invalid Email OTP config: %w", err)
		}
		return emailotp.New(cfg, logger), record, nil

	default:
		return nil, nil, fmt.Errorf("unsupported MFA provider type: %s", record.ProviderType)
	}
}

// buildMFAClient loads the effective MFA provider for an IDP and creates the appropriate client.
// Returns nil, nil, nil when no MFA provider is configured for the IDP.
func (h *MFAHandler) buildMFAClient(r *http.Request, idpID string) (mfa.Provider, *db.MFAProviderRecord, error) {
	return buildMFAClientForIDP(r.Context(), h.store, h.crypto, idpID, h.logger)
}

// resolveUserEmail looks up a user's notification email from the IDP directory.
func (h *MFAHandler) resolveUserEmail(r *http.Request, idpID, username string) (string, error) {
	provider, ok := h.registry.Get(idpID)
	if !ok {
		return "", fmt.Errorf("IDP %s not found in registry", idpID)
	}

	// Resolve user DN.
	userDN, err := provider.SearchUser(r.Context(), "uid", username)
	if err != nil {
		userDN, err = provider.SearchUser(r.Context(), "sAMAccountName", username)
	}
	if err != nil {
		return "", fmt.Errorf("user %q not found in directory: %w", username, err)
	}

	// Load IDP config to find the notification email attribute.
	idpRecord, err := h.store.GetIDP(r.Context(), idpID)
	if err != nil {
		return "", fmt.Errorf("loading IDP record: %w", err)
	}

	var idpCfg idp.Config
	if err := json.Unmarshal([]byte(idpRecord.ConfigJSON), &idpCfg); err != nil {
		return "", fmt.Errorf("parsing IDP config: %w", err)
	}

	emailAttr := idpCfg.NotificationEmailAttr
	if emailAttr == "" {
		emailAttr = "mail"
	}

	userEmail, err := provider.GetUserAttribute(r.Context(), userDN, emailAttr)
	if err != nil {
		return "", fmt.Errorf("getting email attribute %q for %q: %w", emailAttr, userDN, err)
	}
	return userEmail, nil
}

// sendOTPEmail sends the OTP code to the user's email address using SMTP config.
func (h *MFAHandler) sendOTPEmail(r *http.Request, otpClient *emailotp.Client, userEmail, otpCode string) error {
	smtpRecord, err := h.store.GetSMTPConfig(r.Context())
	if err != nil || smtpRecord == nil {
		return fmt.Errorf("SMTP not configured")
	}

	emailCfg, err := buildEmailConfigFromRecord(smtpRecord, h.crypto)
	if err != nil {
		return fmt.Errorf("building email config: %w", err)
	}

	body := buildOTPEmailBody(otpCode, otpClient.TTLMinutes())
	subject := otpClient.EmailSubject()

	return email.SendHTML(emailCfg, userEmail, subject, body)
}

// ShowMFA initiates the MFA flow for password change verification.
// GET /mfa
func (h *MFAHandler) ShowMFA(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	h.logger.Debug("initiating MFA for password operation", "username", sess.Username)

	errorRedirect := "/dashboard"
	if sess.UserType == "reset" {
		errorRedirect = "/forgot-password"
	}

	client, record, err := h.buildMFAClient(r, sess.ProviderID)
	if err != nil {
		h.logger.Error("failed to build MFA client", "error", err)
		// If MFA was pending from login, clear it and fail open.
		if sess.MFAPending {
			_ = h.store.UpdateSessionMFA(r.Context(), sess.ID, false, "")
			h.logger.Warn("MFA client error during login MFA, failing open", "username", sess.Username)
			http.Redirect(w, r, h.postMFARedirect(sess), http.StatusFound)
			return
		}
		h.sessions.SetFlash(w, r, "error", "MFA is not configured. Please contact your administrator.")
		http.Redirect(w, r, errorRedirect, http.StatusFound)
		return
	}
	if client == nil {
		// No MFA configured. If pending from login, clear and fail open.
		if sess.MFAPending {
			_ = h.store.UpdateSessionMFA(r.Context(), sess.ID, false, "")
		}
		http.Redirect(w, r, h.postMFARedirect(sess), http.StatusFound)
		return
	}

	// For email OTP: if the session already has a valid unexpired code, just
	// re-render the form — don't generate a new code or send another email.
	// This prevents duplicate emails when the user navigates back to GET /mfa
	// after submitting a wrong code (the POST result sits at /mfa/verify-otp
	// and pressing back re-hits this endpoint).
	if mfa.ProviderType(record.ProviderType) == mfa.ProviderTypeEmail && emailotp.IsStateValid(sess.MFAState) {
		h.logger.Debug("reusing existing OTP state for re-render", "username", sess.Username)
		h.renderOTPForm(w, r, client.(*emailotp.Client).TTLMinutes(), "")
		return
	}

	authURL, state, err := client.Initiate(r.Context(), sess.Username)
	if err != nil {
		h.logger.Error("failed to initiate MFA", "error", err, "username", sess.Username)
		// If MFA was pending from login, clear and fail open.
		if sess.MFAPending {
			_ = h.store.UpdateSessionMFA(r.Context(), sess.ID, false, "")
			h.logger.Warn("MFA initiation failed during login MFA, failing open", "username", sess.Username)
			http.Redirect(w, r, h.postMFARedirect(sess), http.StatusFound)
			return
		}
		h.sessions.SetFlash(w, r, "error", "Failed to start MFA verification. Please try again.")
		http.Redirect(w, r, errorRedirect, http.StatusFound)
		return
	}

	if err := h.store.UpdateSessionMFA(r.Context(), sess.ID, true, state); err != nil {
		h.logger.Error("failed to save MFA state", "error", err)
		h.sessions.SetFlash(w, r, "error", "Internal error. Please try again.")
		http.Redirect(w, r, errorRedirect, http.StatusFound)
		return
	}

	switch mfa.ProviderType(record.ProviderType) {
	case mfa.ProviderTypeEmail:
		otpClient := client.(*emailotp.Client)
		otpCode := emailotp.ExtractCode(state)

		userEmail, err := h.resolveUserEmail(r, sess.ProviderID, sess.Username)
		if err != nil {
			h.logger.Error("failed to resolve user email for OTP", "error", err, "username", sess.Username)
			h.sessions.SetFlash(w, r, "error", "Could not determine your email address. Please contact your administrator.")
			http.Redirect(w, r, errorRedirect, http.StatusFound)
			return
		}

		if err := h.sendOTPEmail(r, otpClient, userEmail, otpCode); err != nil {
			h.logger.Error("failed to send OTP email", "error", err, "username", sess.Username)
			h.sessions.SetFlash(w, r, "error", "Failed to send verification code. Please try again.")
			http.Redirect(w, r, errorRedirect, http.StatusFound)
			return
		}

		h.logger.Debug("OTP email sent", "username", sess.Username)
		h.renderOTPForm(w, r, otpClient.TTLMinutes(), "")

	default:
		// DUO and any future redirect-based providers.
		h.logger.Debug("redirecting to MFA provider", "type", record.ProviderType, "username", sess.Username)
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// Callback handles the DUO MFA callback after verification.
// GET /mfa/callback
func (h *MFAHandler) Callback(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	errorRedirect := "/dashboard"
	if sess.UserType == "reset" {
		errorRedirect = "/forgot-password"
	}

	duoCode := r.URL.Query().Get("duo_code")
	state := r.URL.Query().Get("state")

	h.logger.Debug("MFA callback",
		"username", sess.Username,
		"has_code", duoCode != "",
		"has_state", state != "",
	)

	if duoCode == "" || state == "" {
		h.logger.Warn("MFA callback missing parameters", "username", sess.Username)
		h.sessions.SetFlash(w, r, "error", "Invalid MFA callback. Please try again.")
		http.Redirect(w, r, errorRedirect, http.StatusFound)
		return
	}

	if sess.MFAState != state {
		h.logger.Warn("MFA state mismatch", "username", sess.Username)
		h.sessions.SetFlash(w, r, "error", "Invalid MFA state. Please try again.")
		http.Redirect(w, r, errorRedirect, http.StatusFound)
		return
	}

	client, _, err := h.buildMFAClient(r, sess.ProviderID)
	if err != nil || client == nil {
		h.logger.Error("failed to build MFA client during callback", "error", err)
		h.sessions.SetFlash(w, r, "error", "MFA verification failed.")
		http.Redirect(w, r, errorRedirect, http.StatusFound)
		return
	}

	if err := client.Verify(r.Context(), duoCode, state, sess.Username); err != nil {
		h.logger.Warn("MFA verification failed", "username", sess.Username, "error", err)
		h.audit.Log(r.Context(), &db.AuditEntry{
			Timestamp: time.Now().UTC(),
			Username:  sess.Username,
			SourceIP:  r.RemoteAddr,
			Action:    audit.ActionMFAVerify,
			Result:    audit.ResultFailure,
			Details:   fmt.Sprintf("MFA verification failed: %v", err),
		})
		h.sessions.SetFlash(w, r, "error", "MFA verification failed. Please try again.")
		http.Redirect(w, r, errorRedirect, http.StatusFound)
		return
	}

	h.completeMFA(w, r, sess)
}

// VerifyOTP handles OTP code submission for email-based MFA.
// POST /mfa/verify-otp
func (h *MFAHandler) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.renderer.RenderError(w, r, http.StatusBadRequest, "Invalid form data")
		return
	}

	client, record, err := h.buildMFAClient(r, sess.ProviderID)
	if err != nil || client == nil || record == nil {
		h.logger.Error("failed to build email OTP client for verify", "error", err)
		h.sessions.SetFlash(w, r, "error", "MFA configuration error.")
		http.Redirect(w, r, "/mfa", http.StatusFound)
		return
	}

	otpClient, ok := client.(*emailotp.Client)
	if !ok {
		h.logger.Error("VerifyOTP called for non-email MFA provider", "type", record.ProviderType)
		http.Redirect(w, r, "/mfa", http.StatusFound)
		return
	}

	code := strings.TrimSpace(r.FormValue("code"))
	if err := client.Verify(r.Context(), code, sess.MFAState, sess.Username); err != nil {
		h.logger.Debug("OTP verification failed", "username", sess.Username, "error", err)
		h.audit.Log(r.Context(), &db.AuditEntry{
			Timestamp: time.Now().UTC(),
			Username:  sess.Username,
			SourceIP:  r.RemoteAddr,
			Action:    audit.ActionMFAVerify,
			Result:    audit.ResultFailure,
			Details:   fmt.Sprintf("Email OTP verification failed: %v", err),
		})

		newAttempts := sess.MFAAttempts + 1
		if newAttempts >= mfaMaxAttempts {
			// Token is dead — clear MFA state so it cannot be retried.
			_ = h.store.UpdateSessionMFA(r.Context(), sess.ID, false, "")
			h.logger.Warn("OTP token invalidated after max attempts", "username", sess.Username, "attempts", newAttempts)
			h.renderOTPForm(w, r, otpClient.TTLMinutes(), "Too many failed attempts. Please request a new code.")
			return
		}

		_ = h.store.UpdateSessionMFAAttempts(r.Context(), sess.ID, newAttempts)

		remaining := mfaMaxAttempts - newAttempts
		errMsg := fmt.Sprintf("Invalid verification code. %d attempt(s) remaining.", remaining)
		if strings.Contains(err.Error(), "expired") {
			errMsg = "Your verification code has expired. Please request a new one."
		}
		h.renderOTPForm(w, r, otpClient.TTLMinutes(), errMsg)
		return
	}

	h.completeMFA(w, r, sess)
}

// ResendOTP re-initiates the email OTP flow, sending a fresh code.
// POST /mfa/resend-otp
func (h *MFAHandler) ResendOTP(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	errorRedirect := "/dashboard"
	if sess.UserType == "reset" {
		errorRedirect = "/forgot-password"
	}

	client, record, err := h.buildMFAClient(r, sess.ProviderID)
	if err != nil || client == nil || record == nil {
		h.logger.Error("failed to build MFA client for resend", "error", err)
		h.sessions.SetFlash(w, r, "error", "MFA configuration error.")
		http.Redirect(w, r, errorRedirect, http.StatusFound)
		return
	}

	otpClient, ok := client.(*emailotp.Client)
	if !ok {
		http.Redirect(w, r, "/mfa", http.StatusFound)
		return
	}

	_, newState, err := client.Initiate(r.Context(), sess.Username)
	if err != nil {
		h.logger.Error("failed to generate new OTP for resend", "error", err)
		h.sessions.SetFlash(w, r, "error", "Failed to generate a new code. Please try again.")
		http.Redirect(w, r, errorRedirect, http.StatusFound)
		return
	}

	if err := h.store.UpdateSessionMFA(r.Context(), sess.ID, true, newState); err != nil {
		h.logger.Error("failed to update session MFA state on resend", "error", err)
		h.sessions.SetFlash(w, r, "error", "Internal error. Please try again.")
		http.Redirect(w, r, errorRedirect, http.StatusFound)
		return
	}

	otpCode := emailotp.ExtractCode(newState)
	userEmail, err := h.resolveUserEmail(r, sess.ProviderID, sess.Username)
	if err != nil {
		h.logger.Error("failed to resolve user email for OTP resend", "error", err)
		h.sessions.SetFlash(w, r, "error", "Could not determine your email address.")
		http.Redirect(w, r, errorRedirect, http.StatusFound)
		return
	}

	if err := h.sendOTPEmail(r, otpClient, userEmail, otpCode); err != nil {
		h.logger.Error("failed to resend OTP email", "error", err)
		h.sessions.SetFlash(w, r, "error", "Failed to send verification code. Please try again.")
		http.Redirect(w, r, errorRedirect, http.StatusFound)
		return
	}

	h.logger.Debug("OTP resent", "username", sess.Username)
	h.renderOTPForm(w, r, otpClient.TTLMinutes(), "")
}

// completeMFA marks the session as MFA-verified and redirects to the appropriate destination.
func (h *MFAHandler) completeMFA(w http.ResponseWriter, r *http.Request, sess *db.Session) {
	if err := h.store.UpdateSessionMFA(r.Context(), sess.ID, false, "verified"); err != nil {
		h.logger.Error("failed to update MFA state", "error", err)
	}

	h.logger.Info("MFA verification successful", "username", sess.Username)
	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp: time.Now().UTC(),
		Username:  sess.Username,
		SourceIP:  r.RemoteAddr,
		Action:    audit.ActionMFAVerify,
		Result:    audit.ResultSuccess,
		Details:   "MFA verified for password operation",
	})

	dest := h.postMFARedirect(sess)
	if sess.UserType == "reset" {
		h.sessions.SetFlash(w, r, "success", "Identity verified. You may now reset your password.")
	} else {
		h.sessions.SetFlash(w, r, "success", "Identity verified. You may now change your password.")
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// postMFARedirect returns the URL to redirect to after successful MFA.
func (h *MFAHandler) postMFARedirect(sess *db.Session) string {
	if sess.UserType == "reset" {
		return "/reset-password"
	}
	return "/dashboard"
}

// renderOTPForm renders the OTP code entry page.
func (h *MFAHandler) renderOTPForm(w http.ResponseWriter, r *http.Request, ttlMinutes int, flashMsg string) {
	var flash map[string]string
	if flashMsg != "" {
		flash = map[string]string{"category": "error", "message": flashMsg}
	}
	h.renderer.Render(w, r, "mfa_otp.html", PageData{
		Title: "Verify Your Identity",
		Flash: flash,
		Data: map[string]any{
			"TTLMinutes": ttlMinutes,
		},
	})
}

// buildEmailConfigFromRecord parses an SMTPConfig record into an email.Config.
func buildEmailConfigFromRecord(rec *db.SMTPConfig, cryptoSvc *crypto.Service) (email.Config, error) {
	type smtpConfigFields struct {
		Host          string `json:"host"`
		Port          string `json:"port"`
		FromAddress   string `json:"from_address"`
		FromName      string `json:"from_name"`
		UseTLS        bool   `json:"use_tls"`
		UseStartTLS   bool   `json:"use_starttls"`
		TLSSkipVerify bool   `json:"tls_skip_verify"`
		Enabled       bool   `json:"enabled"`
	}
	var fields smtpConfigFields
	if err := json.Unmarshal([]byte(rec.ConfigJSON), &fields); err != nil {
		return email.Config{}, fmt.Errorf("parsing SMTP config: %w", err)
	}
	if !fields.Enabled {
		return email.Config{}, fmt.Errorf("SMTP is not enabled")
	}

	type smtpSecrets struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	var secrets smtpSecrets
	if len(rec.SecretBlob) > 0 {
		plaintext, err := cryptoSvc.Decrypt(rec.SecretBlob)
		if err != nil {
			return email.Config{}, fmt.Errorf("decrypting SMTP secrets: %w", err)
		}
		if err := json.Unmarshal(plaintext, &secrets); err != nil {
			return email.Config{}, fmt.Errorf("parsing SMTP secrets: %w", err)
		}
	}

	return email.Config{
		Host:          fields.Host,
		Port:          fields.Port,
		FromAddress:   fields.FromAddress,
		FromName:      fields.FromName,
		UseTLS:        fields.UseTLS,
		UseStartTLS:   fields.UseStartTLS,
		TLSSkipVerify: fields.TLSSkipVerify,
		Username:      secrets.Username,
		Password:      secrets.Password,
	}, nil
}

// otpEmailTemplate is the HTML body for OTP emails.
var otpEmailTemplate = template.Must(template.New("otp").Parse(`<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;max-width:480px;margin:40px auto;color:#333">
  <h2 style="color:#1a73e8">Verification Code</h2>
  <p>Your one-time verification code is:</p>
  <p style="font-size:2em;font-weight:bold;letter-spacing:0.2em;color:#1a73e8">{{.OTP}}</p>
  <p>This code expires in <strong>{{.TTL}} minutes</strong>.</p>
  <p style="color:#888;font-size:0.9em">If you did not request this code, you can ignore this email.</p>
</body>
</html>`))

// buildOTPEmailBody renders the OTP email HTML body.
func buildOTPEmailBody(otp string, ttlMinutes int) string {
	var sb strings.Builder
	_ = otpEmailTemplate.Execute(&sb, map[string]any{
		"OTP": otp,
		"TTL": ttlMinutes,
	})
	return sb.String()
}
