package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/mfa"
	"github.com/hanej/passport/internal/mfa/duo"
)

// AdminMFAHandler handles MFA provider management in the admin UI.
type AdminMFAHandler struct {
	store    db.Store
	crypto   *crypto.Service
	renderer *Renderer
	audit    *audit.Logger
	logger   *slog.Logger
}

// NewAdminMFAHandler creates a new AdminMFAHandler.
func NewAdminMFAHandler(
	store db.Store,
	cryptoSvc *crypto.Service,
	renderer *Renderer,
	auditLogger *audit.Logger,
	logger *slog.Logger,
) *AdminMFAHandler {
	return &AdminMFAHandler{
		store:    store,
		crypto:   cryptoSvc,
		renderer: renderer,
		audit:    auditLogger,
		logger:   logger,
	}
}

// List renders the MFA providers list page.
// GET /admin/mfa
func (h *AdminMFAHandler) List(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	providers, err := h.store.ListMFAProviders(r.Context())
	if err != nil {
		h.logger.Error("failed to list MFA providers", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to load MFA providers")
		return
	}

	defaultIDPtr, err := h.store.GetDefaultMFAProviderID(r.Context())
	if err != nil {
		h.logger.Error("failed to get default MFA provider ID", "error", err)
	}
	defaultID := ""
	if defaultIDPtr != nil {
		defaultID = *defaultIDPtr
	}

	requireMFAOnLogin, err := h.store.GetMFALoginRequired(r.Context())
	if err != nil {
		h.logger.Error("failed to get MFA login required setting", "error", err)
	}

	h.renderer.Render(w, r, "admin_mfa_list.html", PageData{
		Title:   "MFA Providers",
		Session: sess,
		Data: map[string]any{
			"Providers":         providers,
			"DefaultMFAID":      defaultID,
			"RequireMFAOnLogin": requireMFAOnLogin,
			"ActivePage":        "mfa",
		},
	})
}

// ShowCreate renders the MFA provider creation form.
// GET /admin/mfa/new
func (h *AdminMFAHandler) ShowCreate(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	h.renderer.Render(w, r, "admin_mfa_form.html", PageData{
		Title:   "Add MFA Provider",
		Session: sess,
		Data: map[string]any{
			"Mode":       "create",
			"ActivePage": "mfa",
		},
	})
}

// Create processes the MFA provider creation form.
// POST /admin/mfa
func (h *AdminMFAHandler) Create(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	if err := r.ParseForm(); err != nil {
		h.renderer.RenderError(w, r, http.StatusBadRequest, "Invalid form data")
		return
	}

	name := r.FormValue("name")
	providerType := r.FormValue("provider_type")

	if name == "" {
		h.renderFormError(w, r, "create", nil, "Name is required", sess)
		return
	}

	if providerType != string(mfa.ProviderTypeDuo) && providerType != string(mfa.ProviderTypeEmail) {
		h.renderFormError(w, r, "create", nil, "Invalid provider type", sess)
		return
	}

	configJSON, secretBlob, err := h.marshalProviderConfig(r, providerType, nil)
	if err != nil {
		h.logger.Error("failed to marshal MFA config", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}

	record := &db.MFAProviderRecord{
		ID:           uuid.New().String(),
		Name:         name,
		ProviderType: providerType,
		Enabled:      false,
		ConfigJSON:   configJSON,
		SecretBlob:   secretBlob,
	}

	if err := h.store.CreateMFAProvider(r.Context(), record); err != nil {
		h.logger.Error("failed to create MFA provider", "error", err)
		h.renderFormError(w, r, "create", nil, "Failed to create MFA provider: "+err.Error(), sess)
		return
	}

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp: time.Now().UTC(),
		Username:  sess.Username,
		SourceIP:  r.RemoteAddr,
		Action:    audit.ActionMFACreate,
		Result:    audit.ResultSuccess,
		Details:   fmt.Sprintf("Created MFA provider %s (%s)", name, record.ID),
	})

	http.Redirect(w, r, "/admin/mfa", http.StatusFound)
}

// ShowEdit renders the MFA provider edit form.
// GET /admin/mfa/{id}/edit
func (h *AdminMFAHandler) ShowEdit(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	id := chi.URLParam(r, "id")

	record, err := h.store.GetMFAProvider(r.Context(), id)
	if err != nil {
		h.renderer.RenderError(w, r, http.StatusNotFound, "MFA provider not found")
		return
	}

	data := map[string]any{
		"Mode":         "edit",
		"Provider":     record,
		"ProviderType": record.ProviderType,
		"ActivePage":   "mfa",
	}

	switch mfa.ProviderType(record.ProviderType) {
	case mfa.ProviderTypeDuo:
		var duoConfig mfa.DuoConfig
		if record.ConfigJSON != "" {
			_ = json.Unmarshal([]byte(record.ConfigJSON), &duoConfig)
		}
		var duoSecrets mfa.DuoSecrets
		if len(record.SecretBlob) > 0 {
			if plaintext, err := h.crypto.Decrypt(record.SecretBlob); err == nil {
				_ = json.Unmarshal(plaintext, &duoSecrets)
			}
		}
		data["Config"] = duoConfig
		data["Secrets"] = duoSecrets

	case mfa.ProviderTypeEmail:
		var emailCfg mfa.EmailOTPConfig
		if record.ConfigJSON != "" {
			_ = json.Unmarshal([]byte(record.ConfigJSON), &emailCfg)
		}
		data["EmailConfig"] = emailCfg
	}

	h.renderer.Render(w, r, "admin_mfa_form.html", PageData{
		Title:   "Edit MFA Provider",
		Session: sess,
		Data:    data,
	})
}

// Update processes the MFA provider edit form.
// POST /admin/mfa/{id}
func (h *AdminMFAHandler) Update(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	id := chi.URLParam(r, "id")

	if err := r.ParseForm(); err != nil {
		h.renderer.RenderError(w, r, http.StatusBadRequest, "Invalid form data")
		return
	}

	record, err := h.store.GetMFAProvider(r.Context(), id)
	if err != nil {
		h.renderer.RenderError(w, r, http.StatusNotFound, "MFA provider not found")
		return
	}

	configJSON, secretBlob, err := h.marshalProviderConfig(r, record.ProviderType, record)
	if err != nil {
		h.logger.Error("failed to marshal MFA config", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}

	record.Name = r.FormValue("name")
	record.ConfigJSON = configJSON
	record.SecretBlob = secretBlob

	if err := h.store.UpdateMFAProvider(r.Context(), record); err != nil {
		h.logger.Error("failed to update MFA provider", "error", err, "id", id)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to update MFA provider")
		return
	}

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp: time.Now().UTC(),
		Username:  sess.Username,
		SourceIP:  r.RemoteAddr,
		Action:    audit.ActionMFAUpdate,
		Result:    audit.ResultSuccess,
		Details:   fmt.Sprintf("Updated MFA provider %s (%s)", record.Name, id),
	})

	http.Redirect(w, r, "/admin/mfa", http.StatusFound)
}

// Delete removes an MFA provider.
// POST /admin/mfa/{id}/delete
func (h *AdminMFAHandler) Delete(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	id := chi.URLParam(r, "id")

	if err := h.store.DeleteMFAProvider(r.Context(), id); err != nil {
		h.logger.Error("failed to delete MFA provider", "error", err, "id", id)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to delete MFA provider")
		return
	}

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp: time.Now().UTC(),
		Username:  sess.Username,
		SourceIP:  r.RemoteAddr,
		Action:    audit.ActionMFADelete,
		Result:    audit.ResultSuccess,
		Details:   fmt.Sprintf("Deleted MFA provider %s", id),
	})

	http.Redirect(w, r, "/admin/mfa", http.StatusFound)
}

// Toggle enables or disables an MFA provider.
// POST /admin/mfa/{id}/toggle
func (h *AdminMFAHandler) Toggle(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	id := chi.URLParam(r, "id")

	record, err := h.store.GetMFAProvider(r.Context(), id)
	if err != nil {
		h.renderer.RenderError(w, r, http.StatusNotFound, "MFA provider not found")
		return
	}

	newEnabled := !record.Enabled
	if err := h.store.ToggleMFAProvider(r.Context(), id, newEnabled); err != nil {
		h.logger.Error("failed to toggle MFA provider", "error", err, "id", id)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to toggle MFA provider")
		return
	}

	status := "enabled"
	if !newEnabled {
		status = "disabled"
	}

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp: time.Now().UTC(),
		Username:  sess.Username,
		SourceIP:  r.RemoteAddr,
		Action:    audit.ActionMFAToggle,
		Result:    audit.ResultSuccess,
		Details:   fmt.Sprintf("MFA provider %s %s", id, status),
	})

	http.Redirect(w, r, "/admin/mfa", http.StatusFound)
}

// TestConnection tests the MFA provider connection. Returns JSON.
// POST /admin/mfa/{id}/test
func (h *AdminMFAHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	record, err := h.store.GetMFAProvider(r.Context(), id)
	if err != nil {
		h.renderer.JSON(w, http.StatusNotFound, map[string]string{
			"status":  "error",
			"message": "MFA provider not found",
		})
		return
	}

	switch mfa.ProviderType(record.ProviderType) {
	case mfa.ProviderTypeDuo:
		var duoConfig mfa.DuoConfig
		if err := json.Unmarshal([]byte(record.ConfigJSON), &duoConfig); err != nil {
			h.renderer.JSON(w, http.StatusInternalServerError, map[string]string{
				"status":  "error",
				"message": "Invalid DUO configuration",
			})
			return
		}
		var duoSecrets mfa.DuoSecrets
		if len(record.SecretBlob) > 0 {
			plaintext, err := h.crypto.Decrypt(record.SecretBlob)
			if err != nil {
				h.renderer.JSON(w, http.StatusInternalServerError, map[string]string{
					"status":  "error",
					"message": "Failed to decrypt secrets",
				})
				return
			}
			if err := json.Unmarshal(plaintext, &duoSecrets); err != nil {
				h.renderer.JSON(w, http.StatusInternalServerError, map[string]string{
					"status":  "error",
					"message": "Invalid secrets data",
				})
				return
			}
		}
		client, err := duo.New(duoConfig, duoSecrets, h.logger)
		if err != nil {
			h.renderer.JSON(w, http.StatusInternalServerError, map[string]string{
				"status":  "error",
				"message": fmt.Sprintf("Failed to create DUO client: %v", err),
			})
			return
		}
		if err := client.HealthCheck(r.Context()); err != nil {
			h.renderer.JSON(w, http.StatusOK, map[string]string{
				"status":  "error",
				"message": fmt.Sprintf("Health check failed: %v", err),
			})
			return
		}
		h.renderer.JSON(w, http.StatusOK, map[string]string{
			"status":  "success",
			"message": "DUO connection successful",
		})

	case mfa.ProviderTypeEmail:
		// Email OTP has no external service to test — SMTP is tested via the SMTP admin page.
		h.renderer.JSON(w, http.StatusOK, map[string]string{
			"status":  "success",
			"message": "Email OTP provider is ready. Test SMTP connectivity via the SMTP settings page.",
		})

	default:
		h.renderer.JSON(w, http.StatusBadRequest, map[string]string{
			"status":  "error",
			"message": "Unknown provider type",
		})
	}
}

// SetDefault sets the global default MFA provider.
// POST /admin/mfa/default
func (h *AdminMFAHandler) SetDefault(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	if err := r.ParseForm(); err != nil {
		h.renderer.RenderError(w, r, http.StatusBadRequest, "Invalid form data")
		return
	}

	idStr := r.FormValue("default_mfa_provider_id")
	var idPtr *string
	if idStr != "" {
		idPtr = &idStr
	}

	if err := h.store.SetDefaultMFAProviderID(r.Context(), idPtr); err != nil {
		h.logger.Error("failed to set default MFA provider", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to save default MFA provider")
		return
	}

	detail := "Cleared default MFA provider"
	if idPtr != nil {
		detail = fmt.Sprintf("Set default MFA provider to %s", *idPtr)
	}
	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp: time.Now().UTC(),
		Username:  sess.Username,
		SourceIP:  r.RemoteAddr,
		Action:    audit.ActionMFAUpdate,
		Result:    audit.ResultSuccess,
		Details:   detail,
	})

	http.Redirect(w, r, "/admin/mfa", http.StatusFound)
}

// marshalProviderConfig encodes config and secrets for the given provider type from form values.
// When updating (existing != nil) and a secret field is blank, the existing secret is preserved.
func (h *AdminMFAHandler) marshalProviderConfig(r *http.Request, providerType string, existing *db.MFAProviderRecord) (configJSON string, secretBlob []byte, err error) {
	switch mfa.ProviderType(providerType) {
	case mfa.ProviderTypeDuo:
		cfg := mfa.DuoConfig{
			APIHostname: r.FormValue("api_hostname"),
			ClientID:    r.FormValue("client_id"),
			RedirectURI: r.FormValue("redirect_uri"),
		}
		cfgBytes, err := json.Marshal(cfg)
		if err != nil {
			return "", nil, fmt.Errorf("marshaling DUO config: %w", err)
		}

		secrets := mfa.DuoSecrets{ClientSecret: r.FormValue("client_secret")}
		if secrets.ClientSecret == "" && existing != nil && len(existing.SecretBlob) > 0 {
			// Preserve existing secret when the field is left blank on edit.
			plaintext, decErr := h.crypto.Decrypt(existing.SecretBlob)
			if decErr == nil {
				var saved mfa.DuoSecrets
				if jsonErr := json.Unmarshal(plaintext, &saved); jsonErr == nil {
					secrets.ClientSecret = saved.ClientSecret
				}
			}
		}
		secretsBytes, err := json.Marshal(secrets)
		if err != nil {
			return "", nil, fmt.Errorf("marshaling DUO secrets: %w", err)
		}
		blob, err := h.crypto.Encrypt(secretsBytes)
		if err != nil {
			return "", nil, fmt.Errorf("encrypting DUO secrets: %w", err)
		}
		return string(cfgBytes), blob, nil

	case mfa.ProviderTypeEmail:
		otpLength := 6
		ttlMinutes := 5
		if v := r.FormValue("otp_length"); v != "" {
			if n, err := parseInt(v); err == nil && n > 0 {
				otpLength = n
			}
		}
		if v := r.FormValue("otp_ttl_minutes"); v != "" {
			if n, err := parseInt(v); err == nil && n > 0 {
				ttlMinutes = n
			}
		}
		cfg := mfa.EmailOTPConfig{
			OTPLength:     otpLength,
			OTPTTLMinutes: ttlMinutes,
			EmailSubject:  r.FormValue("email_subject"),
		}
		if cfg.EmailSubject == "" {
			cfg.EmailSubject = "Your verification code"
		}
		cfgBytes, err := json.Marshal(cfg)
		if err != nil {
			return "", nil, fmt.Errorf("marshaling Email OTP config: %w", err)
		}
		return string(cfgBytes), nil, nil

	default:
		return "", nil, fmt.Errorf("unknown provider type: %s", providerType)
	}
}

// renderFormError re-renders the MFA provider form with an error message.
func (h *AdminMFAHandler) renderFormError(w http.ResponseWriter, r *http.Request, mode string, provider *db.MFAProviderRecord, message string, sess *db.Session) {
	data := map[string]any{
		"Mode":       mode,
		"ActivePage": "mfa",
	}
	if provider != nil {
		data["Provider"] = provider
		data["ProviderType"] = provider.ProviderType
	}
	title := "Add MFA Provider"
	if mode == "edit" {
		title = "Edit MFA Provider"
	}
	h.renderer.Render(w, r, "admin_mfa_form.html", PageData{
		Title:   title,
		Session: sess,
		Flash:   map[string]string{"category": "error", "message": message},
		Data:    data,
	})
}

// parseInt parses a strict decimal integer string (no trailing garbage accepted).
func parseInt(s string) (int, error) {
	return strconv.Atoi(strings.TrimSpace(s))
}

// ToggleMFALogin toggles the require-MFA-on-login setting.
// POST /admin/mfa/login-toggle
func (h *AdminMFAHandler) ToggleMFALogin(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	current, err := h.store.GetMFALoginRequired(r.Context())
	if err != nil {
		h.logger.Error("failed to read MFA login required setting", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to read MFA setting")
		return
	}

	newVal := !current
	if err := h.store.SetMFALoginRequired(r.Context(), newVal); err != nil {
		h.logger.Error("failed to set MFA login required", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to save MFA setting")
		return
	}

	detail := "Disabled MFA on login"
	if newVal {
		detail = "Enabled MFA on login"
	}
	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp: time.Now().UTC(),
		Username:  sess.Username,
		SourceIP:  r.RemoteAddr,
		Action:    audit.ActionMFAUpdate,
		Result:    audit.ResultSuccess,
		Details:   detail,
	})

	http.Redirect(w, r, "/admin/mfa", http.StatusFound)
}
