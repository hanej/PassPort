package handler

import (
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/go-ldap/ldap/v3"
	"github.com/gorilla/csrf"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
	"github.com/hanej/passport/internal/idp/ad"
	"github.com/hanej/passport/internal/idp/freeipa"
)

// AdminIDPHandler handles IDP management in the admin UI.
type AdminIDPHandler struct {
	store      db.Store
	crypto     *crypto.Service
	registry   *idp.Registry
	renderer   *Renderer
	audit      *audit.Logger
	logger     *slog.Logger
	uploadsDir string
	connector  idp.LDAPConnector
}

// NewAdminIDPHandler creates a new AdminIDPHandler.
func NewAdminIDPHandler(
	store db.Store,
	cryptoSvc *crypto.Service,
	registry *idp.Registry,
	renderer *Renderer,
	auditLogger *audit.Logger,
	logger *slog.Logger,
	uploadsDir string,
) *AdminIDPHandler {
	return &AdminIDPHandler{
		store:      store,
		crypto:     cryptoSvc,
		registry:   registry,
		renderer:   renderer,
		audit:      auditLogger,
		logger:     logger,
		uploadsDir: uploadsDir,
		connector:  &idp.DefaultLDAPConnector{},
	}
}

// handleLogoUpload processes an optional logo file upload for an IDP.
// Returns the logo URL path (e.g., "/uploads/idp-logo-corp-ad.png") or the existing value.
func (h *AdminIDPHandler) handleLogoUpload(r *http.Request, idpID, currentLogoURL string) string {
	if r.FormValue("remove_logo") == "1" {
		if currentLogoURL != "" {
			os.Remove(filepath.Join(h.uploadsDir, filepath.Base(currentLogoURL)))
		}
		return ""
	}

	file, header, err := r.FormFile("logo_file")
	if err != nil {
		return currentLogoURL // no new file uploaded
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(header.Filename))
	if ext != ".png" && ext != ".jpg" && ext != ".jpeg" && ext != ".svg" && ext != ".gif" && ext != ".webp" && ext != ".ico" {
		return currentLogoURL
	}

	destName := "idp-logo-" + idpID + ext
	destPath := filepath.Join(h.uploadsDir, destName)

	out, err := os.Create(destPath)
	if err != nil {
		h.logger.Error("failed to save IDP logo", "path", destPath, "error", err)
		return currentLogoURL
	}
	defer out.Close()

	if _, err := io.Copy(out, file); err != nil {
		h.logger.Error("failed to write IDP logo", "path", destPath, "error", err)
		return currentLogoURL
	}

	return "/uploads/" + destName
}

// List renders the IDP list page.
// GET /admin/idp
// IDPListItem is a view model for the IDP list page with parsed config fields.
type IDPListItem struct {
	db.IdentityProviderRecord
	Endpoint string
}

func (h *AdminIDPHandler) List(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	idps, err := h.store.ListIDPs(r.Context())
	if err != nil {
		h.logger.Error("failed to list IDPs", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to load identity providers")
		return
	}

	// Build view models with parsed endpoint from ConfigJSON.
	items := make([]IDPListItem, len(idps))
	for i, rec := range idps {
		items[i] = IDPListItem{IdentityProviderRecord: rec}
		var cfg idp.Config
		if err := json.Unmarshal([]byte(rec.ConfigJSON), &cfg); err == nil {
			items[i].Endpoint = cfg.Endpoint
		}
	}

	h.renderer.Render(w, r, "admin_idp_list.html", PageData{
		Title:     "Identity Providers",
		Session:   sess,
		CSRFField: csrf.TemplateField(r),
		Data: map[string]any{
			"IDPs":       items,
			"ActivePage": "idp",
		},
	})
}

// ShowCreate renders the IDP creation form.
// GET /admin/idp/new
func (h *AdminIDPHandler) ShowCreate(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	mfaProviders, _ := h.store.ListMFAProviders(r.Context())
	defaultMFAIDPtr, _ := h.store.GetDefaultMFAProviderID(r.Context())
	defaultMFAID := ""
	if defaultMFAIDPtr != nil {
		defaultMFAID = *defaultMFAIDPtr
	}
	defaultMFAName := ""
	for _, p := range mfaProviders {
		if p.ID == defaultMFAID {
			defaultMFAName = p.Name
			break
		}
	}

	h.renderer.Render(w, r, "admin_idp_form.html", PageData{
		Title:     "Add Identity Provider",
		Session:   sess,
		CSRFField: csrf.TemplateField(r),
		Data: map[string]any{
			"Mode":           "create",
			"ActivePage":     "idp",
			"MFAProviders":   mfaProviders,
			"DefaultMFAID":   defaultMFAID,
			"DefaultMFAName": defaultMFAName,
			"CurrentMFAID":   "",
		},
	})
}

// Create processes the IDP creation form.
// POST /admin/idp
func (h *AdminIDPHandler) Create(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	// Try multipart (for logo upload), fall back to standard form.
	if err := r.ParseMultipartForm(5 << 20); err != nil {
		if parseErr := r.ParseForm(); parseErr != nil {
			h.renderer.RenderError(w, r, http.StatusBadRequest, "Invalid form data")
			return
		}
	}

	idpID := r.FormValue("id")

	h.logger.Debug("Create IDP called",
		"idp_id", idpID,
		"type", r.FormValue("provider_type"),
	)

	if idpID == "" {
		h.renderer.Render(w, r, "admin_idp_form.html", PageData{
			Title:     "Add Identity Provider",
			Session:   sess,
			CSRFField: csrf.TemplateField(r),
			Flash:     map[string]string{"category": "error", "message": "ID is required"},
			Data:      map[string]any{"Mode": "create"},
		})
		return
	}

	cfg := h.parseIDPConfig(r)

	configJSON, err := json.Marshal(cfg)
	if err != nil {
		h.logger.Error("failed to marshal IDP config", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}

	secrets := idp.Secrets{
		ServiceAccountUsername: r.FormValue("service_account_username"),
		ServiceAccountPassword: r.FormValue("service_account_password"),
	}

	secretBlob, err := h.encryptSecrets(secrets)
	if err != nil {
		h.logger.Error("failed to encrypt IDP secrets", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}

	logoURL := h.handleLogoUpload(r, idpID, "")

	var mfaProviderID *string
	if v := r.FormValue("mfa_provider_id"); v != "" {
		mfaProviderID = &v
	}

	record := &db.IdentityProviderRecord{
		ID:            idpID,
		FriendlyName:  r.FormValue("friendly_name"),
		Description:   r.FormValue("description"),
		ProviderType:  r.FormValue("provider_type"),
		Enabled:       true,
		LogoURL:       logoURL,
		MFAProviderID: mfaProviderID,
		ConfigJSON:    string(configJSON),
		SecretBlob:    secretBlob,
	}

	if err := h.store.CreateIDP(r.Context(), record); err != nil {
		h.logger.Error("failed to create IDP", "error", err)
		h.renderer.Render(w, r, "admin_idp_form.html", PageData{
			Title:     "Add Identity Provider",
			Session:   sess,
			CSRFField: csrf.TemplateField(r),
			Flash:     map[string]string{"category": "error", "message": "Failed to create identity provider: " + err.Error()},
			Data:      map[string]any{"Mode": "create"},
		})
		return
	}

	h.logger.Debug("IDP created successfully",
		"idp_id", idpID,
	)

	// Save attribute mappings.
	mappings := h.parseAttributeMappings(r, idpID)
	if len(mappings) > 0 {
		if err := h.store.SetAttributeMappings(r.Context(), idpID, mappings); err != nil {
			h.logger.Error("failed to save attribute mappings", "error", err, "idp_id", idpID)
		}
	}

	// Save correlation rule.
	rule := h.parseCorrelationRule(r, idpID)
	if rule != nil {
		if err := h.store.SetCorrelationRule(r.Context(), rule); err != nil {
			h.logger.Error("failed to save correlation rule", "error", err, "idp_id", idpID)
		}
	}

	// Register the provider in the live registry so it's immediately available.
	if err := h.registerProvider(r.Context(), record); err != nil {
		h.logger.Error("provider saved but failed to register", "idp_id", idpID, "error", err)
	}

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp:  time.Now().UTC(),
		Username:   sess.Username,
		SourceIP:   r.RemoteAddr,
		Action:     audit.ActionIDPCreate,
		ProviderID: idpID,
		Result:     audit.ResultSuccess,
		Details:    fmt.Sprintf("Created IDP %q (%s)", record.FriendlyName, record.ProviderType),
	})

	http.Redirect(w, r, "/admin/idp", http.StatusFound)
}

// ShowEdit renders the IDP edit form.
// GET /admin/idp/{id}/edit
func (h *AdminIDPHandler) ShowEdit(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	idpID := chi.URLParam(r, "id")

	h.logger.Debug("ShowEdit called",
		"idp_id", idpID,
	)

	record, err := h.store.GetIDP(r.Context(), idpID)
	if err != nil {
		h.logger.Error("failed to load IDP", "error", err, "idp_id", idpID)
		h.renderer.RenderError(w, r, http.StatusNotFound, "Identity provider not found")
		return
	}

	var cfg idp.Config
	if err := json.Unmarshal([]byte(record.ConfigJSON), &cfg); err != nil {
		h.logger.Error("failed to unmarshal IDP config", "error", err, "idp_id", idpID)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}

	var secrets idp.Secrets
	if len(record.SecretBlob) > 0 {
		plaintext, err := h.crypto.Decrypt(record.SecretBlob)
		if err != nil {
			h.logger.Error("failed to decrypt IDP secrets", "error", err, "idp_id", idpID)
			h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
			return
		}
		if err := json.Unmarshal(plaintext, &secrets); err != nil {
			h.logger.Error("failed to unmarshal IDP secrets", "error", err, "idp_id", idpID)
			h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
			return
		}
	}

	mappings, err := h.store.ListAttributeMappings(r.Context(), idpID)
	if err != nil {
		h.logger.Error("failed to load attribute mappings", "error", err, "idp_id", idpID)
	}

	rule, err := h.store.GetCorrelationRule(r.Context(), idpID)
	if err != nil {
		h.logger.Debug("no correlation rule for IDP", "idp_id", idpID)
		rule = &db.CorrelationRule{}
	}

	h.logger.Debug("ShowEdit loaded record, config, and mappings",
		"idp_id", idpID,
		"mapping_count", len(mappings),
	)

	mfaProviders, _ := h.store.ListMFAProviders(r.Context())
	defaultMFAIDPtr, _ := h.store.GetDefaultMFAProviderID(r.Context())
	defaultMFAID := ""
	if defaultMFAIDPtr != nil {
		defaultMFAID = *defaultMFAIDPtr
	}
	defaultMFAName := ""
	for _, p := range mfaProviders {
		if p.ID == defaultMFAID {
			defaultMFAName = p.Name
			break
		}
	}
	currentMFAID := ""
	if record.MFAProviderID != nil {
		currentMFAID = *record.MFAProviderID
	}

	h.renderer.Render(w, r, "admin_idp_form.html", PageData{
		Title:     "Edit Identity Provider",
		Session:   sess,
		CSRFField: csrf.TemplateField(r),
		Data: map[string]any{
			"Mode":           "edit",
			"IDP":            record,
			"Config":         cfg,
			"Secrets":        secrets,
			"Mappings":       mappings,
			"Rule":           rule,
			"ActivePage":     "idp",
			"MFAProviders":   mfaProviders,
			"DefaultMFAID":   defaultMFAID,
			"DefaultMFAName": defaultMFAName,
			"CurrentMFAID":   currentMFAID,
		},
	})
}

// Update processes the IDP edit form.
// POST /admin/idp/{id}
func (h *AdminIDPHandler) Update(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	idpID := chi.URLParam(r, "id")

	h.logger.Debug("Update IDP called",
		"idp_id", idpID,
	)

	// Try multipart (for logo upload), fall back to standard form.
	if err := r.ParseMultipartForm(5 << 20); err != nil {
		if parseErr := r.ParseForm(); parseErr != nil {
			h.renderer.RenderError(w, r, http.StatusBadRequest, "Invalid form data")
			return
		}
	}

	record, err := h.store.GetIDP(r.Context(), idpID)
	if err != nil {
		h.logger.Error("failed to load IDP for update", "error", err, "idp_id", idpID)
		h.renderer.RenderError(w, r, http.StatusNotFound, "Identity provider not found")
		return
	}

	cfg := h.parseIDPConfig(r)
	configJSON, err := json.Marshal(cfg)
	if err != nil {
		h.logger.Error("failed to marshal IDP config", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}

	// Build secrets, preserving saved values when form fields are blank.
	secrets := idp.Secrets{
		ServiceAccountUsername: r.FormValue("service_account_username"),
		ServiceAccountPassword: r.FormValue("service_account_password"),
	}
	if secrets.ServiceAccountUsername == "" || secrets.ServiceAccountPassword == "" {
		// Load existing secrets so we don't wipe them on save.
		if len(record.SecretBlob) > 0 {
			plaintext, decErr := h.crypto.Decrypt(record.SecretBlob)
			if decErr == nil {
				var saved idp.Secrets
				if jsonErr := json.Unmarshal(plaintext, &saved); jsonErr == nil {
					if secrets.ServiceAccountUsername == "" {
						secrets.ServiceAccountUsername = saved.ServiceAccountUsername
					}
					if secrets.ServiceAccountPassword == "" {
						secrets.ServiceAccountPassword = saved.ServiceAccountPassword
					}
				}
			}
		}
	}

	secretBlob, err := h.encryptSecrets(secrets)
	if err != nil {
		h.logger.Error("failed to encrypt IDP secrets", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}

	// Capture old values for audit diff.
	oldName := record.FriendlyName
	oldDesc := record.Description
	oldType := record.ProviderType
	oldLogo := record.LogoURL
	var oldCfg idp.Config
	_ = json.Unmarshal([]byte(record.ConfigJSON), &oldCfg)
	var oldSecrets idp.Secrets
	if len(record.SecretBlob) > 0 {
		if pt, decErr := h.crypto.Decrypt(record.SecretBlob); decErr == nil {
			_ = json.Unmarshal(pt, &oldSecrets)
		}
	}

	record.FriendlyName = r.FormValue("friendly_name")
	record.Description = r.FormValue("description")
	record.ProviderType = r.FormValue("provider_type")
	record.LogoURL = h.handleLogoUpload(r, idpID, record.LogoURL)
	record.ConfigJSON = string(configJSON)
	record.SecretBlob = secretBlob
	if v := r.FormValue("mfa_provider_id"); v != "" {
		record.MFAProviderID = &v
	} else {
		record.MFAProviderID = nil
	}

	if err := h.store.UpdateIDP(r.Context(), record); err != nil {
		h.logger.Error("failed to update IDP", "error", err, "idp_id", idpID)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to update identity provider")
		return
	}

	// Update attribute mappings.
	mappings := h.parseAttributeMappings(r, idpID)
	if err := h.store.SetAttributeMappings(r.Context(), idpID, mappings); err != nil {
		h.logger.Error("failed to save attribute mappings", "error", err, "idp_id", idpID)
	}

	// Update correlation rule.
	rule := h.parseCorrelationRule(r, idpID)
	if rule != nil {
		if err := h.store.SetCorrelationRule(r.Context(), rule); err != nil {
			h.logger.Error("failed to save correlation rule", "error", err, "idp_id", idpID)
		}
	} else {
		if err := h.store.DeleteCorrelationRule(r.Context(), idpID); err != nil {
			h.logger.Error("failed to delete correlation rule", "error", err, "idp_id", idpID)
		}
	}

	// Re-register the provider with updated config if it's enabled.
	if record.Enabled {
		if err := h.registerProvider(r.Context(), record); err != nil {
			h.logger.Error("provider updated but failed to re-register", "idp_id", idpID, "error", err)
		}
	}

	h.logger.Debug("IDP updated successfully",
		"idp_id", idpID,
	)

	// Build change summary for audit log.
	var changes []string
	if oldName != record.FriendlyName {
		changes = append(changes, fmt.Sprintf("name: %q → %q", oldName, record.FriendlyName))
	}
	if oldDesc != record.Description {
		changes = append(changes, fmt.Sprintf("description: %q → %q", oldDesc, record.Description))
	}
	if oldType != record.ProviderType {
		changes = append(changes, fmt.Sprintf("type: %s → %s", oldType, record.ProviderType))
	}
	if oldLogo != record.LogoURL {
		changes = append(changes, fmt.Sprintf("logo: %q → %q", oldLogo, record.LogoURL))
	}
	if oldCfg.Endpoint != cfg.Endpoint {
		changes = append(changes, fmt.Sprintf("endpoint: %s → %s", oldCfg.Endpoint, cfg.Endpoint))
	}
	if oldCfg.Protocol != cfg.Protocol {
		changes = append(changes, fmt.Sprintf("protocol: %s → %s", oldCfg.Protocol, cfg.Protocol))
	}
	if oldCfg.BaseDN != cfg.BaseDN {
		changes = append(changes, fmt.Sprintf("base_dn: %s → %s", oldCfg.BaseDN, cfg.BaseDN))
	}
	if oldCfg.UserSearchBase != cfg.UserSearchBase {
		changes = append(changes, fmt.Sprintf("user_search_base: %s → %s", oldCfg.UserSearchBase, cfg.UserSearchBase))
	}
	if oldCfg.GroupSearchBase != cfg.GroupSearchBase {
		changes = append(changes, fmt.Sprintf("group_search_base: %s → %s", oldCfg.GroupSearchBase, cfg.GroupSearchBase))
	}
	if oldCfg.TLSSkipVerify != cfg.TLSSkipVerify {
		changes = append(changes, fmt.Sprintf("tls_skip_verify: %v → %v", oldCfg.TLSSkipVerify, cfg.TLSSkipVerify))
	}
	if oldCfg.Timeout != cfg.Timeout {
		changes = append(changes, fmt.Sprintf("timeout: %d → %d", oldCfg.Timeout, cfg.Timeout))
	}
	if oldCfg.SendNotification != cfg.SendNotification {
		changes = append(changes, fmt.Sprintf("send_notification: %v → %v", oldCfg.SendNotification, cfg.SendNotification))
	}
	if oldCfg.NotificationEmailAttr != cfg.NotificationEmailAttr {
		changes = append(changes, fmt.Sprintf("notification_email_attr: %s → %s", oldCfg.NotificationEmailAttr, cfg.NotificationEmailAttr))
	}
	if oldCfg.PasswordComplexityHint != cfg.PasswordComplexityHint {
		changes = append(changes, "password_complexity_hint: (changed)")
	}
	// Note credential changes without logging the actual values.
	if oldSecrets.ServiceAccountUsername != secrets.ServiceAccountUsername {
		changes = append(changes, "service_account_username: (changed)")
	}
	if r.FormValue("service_account_password") != "" {
		changes = append(changes, "service_account_password: (changed)")
	}

	details := fmt.Sprintf("Updated IDP %q", record.FriendlyName)
	if len(changes) > 0 {
		details += ": " + strings.Join(changes, "; ")
	} else {
		details += " (no field changes)"
	}

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp:  time.Now().UTC(),
		Username:   sess.Username,
		SourceIP:   r.RemoteAddr,
		Action:     audit.ActionIDPUpdate,
		ProviderID: idpID,
		Result:     audit.ResultSuccess,
		Details:    details,
	})

	http.Redirect(w, r, "/admin/idp", http.StatusFound)
}

// Delete removes an IDP.
// POST /admin/idp/{id}/delete
func (h *AdminIDPHandler) Delete(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	idpID := chi.URLParam(r, "id")

	h.logger.Debug("Delete IDP called",
		"idp_id", idpID,
	)

	if err := h.store.DeleteIDP(r.Context(), idpID); err != nil {
		h.logger.Error("failed to delete IDP", "error", err, "idp_id", idpID)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to delete identity provider")
		return
	}

	h.registry.Unregister(idpID)

	h.logger.Debug("IDP deleted successfully",
		"idp_id", idpID,
	)

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp:  time.Now().UTC(),
		Username:   sess.Username,
		SourceIP:   r.RemoteAddr,
		Action:     audit.ActionIDPDelete,
		ProviderID: idpID,
		Result:     audit.ResultSuccess,
		Details:    fmt.Sprintf("Deleted IDP %s", idpID),
	})

	http.Redirect(w, r, "/admin/idp", http.StatusFound)
}

// Toggle enables or disables an IDP.
// POST /admin/idp/{id}/toggle
func (h *AdminIDPHandler) Toggle(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	idpID := chi.URLParam(r, "id")

	h.logger.Debug("Toggle IDP called",
		"idp_id", idpID,
	)

	record, err := h.store.GetIDP(r.Context(), idpID)
	if err != nil {
		h.logger.Error("failed to load IDP for toggle", "error", err, "idp_id", idpID)
		h.renderer.RenderError(w, r, http.StatusNotFound, "Identity provider not found")
		return
	}

	newEnabled := !record.Enabled
	if err := h.store.ToggleIDP(r.Context(), idpID, newEnabled); err != nil {
		h.logger.Error("failed to toggle IDP", "error", err, "idp_id", idpID)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to toggle identity provider")
		return
	}

	if newEnabled {
		if err := h.registerProvider(r.Context(), record); err != nil {
			h.logger.Error("failed to register provider on enable", "idp_id", idpID, "error", err)
		}
	} else {
		h.registry.Unregister(idpID)
		h.logger.Info("provider unregistered", "idp_id", idpID)
	}

	status := "enabled"
	if !newEnabled {
		status = "disabled"
	}

	h.logger.Debug("IDP toggled",
		"idp_id", idpID,
		"new_state", status,
	)

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp:  time.Now().UTC(),
		Username:   sess.Username,
		SourceIP:   r.RemoteAddr,
		Action:     audit.ActionIDPToggle,
		ProviderID: idpID,
		Result:     audit.ResultSuccess,
		Details:    fmt.Sprintf("IDP %s %s", idpID, status),
	})

	http.Redirect(w, r, "/admin/idp", http.StatusFound)
}

// TestConnection tests the IDP connection. Returns JSON.
// POST /admin/idp/{id}/test
func (h *AdminIDPHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	idpID := chi.URLParam(r, "id")

	h.logger.Debug("TestConnection called",
		"idp_id", idpID,
	)

	record, err := h.store.GetIDP(r.Context(), idpID)
	if err != nil {
		h.renderer.JSON(w, http.StatusNotFound, map[string]string{
			"status":  "error",
			"message": "Identity provider not found",
		})
		return
	}

	var cfg idp.Config
	if err := json.Unmarshal([]byte(record.ConfigJSON), &cfg); err != nil {
		h.renderer.JSON(w, http.StatusInternalServerError, map[string]string{
			"status":  "error",
			"message": "Invalid IDP configuration",
		})
		return
	}

	var secrets idp.Secrets
	if len(record.SecretBlob) > 0 {
		plaintext, err := h.crypto.Decrypt(record.SecretBlob)
		if err != nil {
			h.renderer.JSON(w, http.StatusInternalServerError, map[string]string{
				"status":  "error",
				"message": "Failed to decrypt secrets",
			})
			return
		}
		if err := json.Unmarshal(plaintext, &secrets); err != nil {
			h.renderer.JSON(w, http.StatusInternalServerError, map[string]string{
				"status":  "error",
				"message": "Invalid secrets data",
			})
			return
		}
	}

	// Create a provider instance to test the connection.
	provider, err := buildProvider(record.ID, record.ProviderType, cfg, secrets, h.logger)
	if err != nil {
		h.renderer.JSON(w, http.StatusInternalServerError, map[string]string{
			"status":  "error",
			"message": "Failed to create provider: " + err.Error(),
		})
		return
	}

	testErr := provider.TestConnection(r.Context())

	result := audit.ResultSuccess
	msg := "Connection successful"
	if testErr != nil {
		result = audit.ResultFailure
		msg = testErr.Error()
	}

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp:  time.Now().UTC(),
		Username:   sess.Username,
		SourceIP:   r.RemoteAddr,
		Action:     audit.ActionIDPTestConnection,
		ProviderID: idpID,
		Result:     result,
		Details:    msg,
	})

	h.logger.Debug("TestConnection result",
		"idp_id", idpID,
		"result", result,
	)

	if testErr != nil {
		h.renderer.JSON(w, http.StatusOK, map[string]string{
			"status":  "error",
			"message": msg,
		})
		return
	}

	h.renderer.JSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": msg,
	})
}

// TestConnectionFromForm tests an IDP connection using form field values (not saved config).
// If the password field is blank and an IDP ID is provided, secrets are loaded from the database.
// POST /admin/idp/test-connection
func (h *AdminIDPHandler) TestConnectionFromForm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderer.JSON(w, http.StatusBadRequest, map[string]string{
			"status":  "error",
			"message": "Invalid form data",
		})
		return
	}

	providerType := r.FormValue("provider_type")
	cfg := h.parseIDPConfig(r)

	secrets := idp.Secrets{
		ServiceAccountUsername: r.FormValue("service_account_username"),
		ServiceAccountPassword: r.FormValue("service_account_password"),
	}

	h.logger.Debug("TestConnectionFromForm called",
		"provider_type", providerType,
		"endpoint", cfg.Endpoint,
		"protocol", cfg.Protocol,
		"tls_skip_verify", cfg.TLSSkipVerify,
	)

	if cfg.Endpoint == "" || cfg.Protocol == "" {
		h.renderer.JSON(w, http.StatusBadRequest, map[string]string{
			"status":  "error",
			"message": "Endpoint and protocol are required",
		})
		return
	}

	// If credentials are missing, try to load saved secrets from the database.
	idpID := r.FormValue("id")
	h.logger.Debug("test connection credentials check",
		"idp_id", idpID,
		"has_username", secrets.ServiceAccountUsername != "",
		"has_password", secrets.ServiceAccountPassword != "",
	)
	if (secrets.ServiceAccountUsername == "" || secrets.ServiceAccountPassword == "") && idpID != "" {
		record, err := h.store.GetIDP(r.Context(), idpID)
		if err != nil {
			h.logger.Debug("could not load saved IDP for credential fallback", "idp_id", idpID, "error", err)
		} else if len(record.SecretBlob) > 0 {
			plaintext, err := h.crypto.Decrypt(record.SecretBlob)
			if err != nil {
				h.logger.Debug("could not decrypt saved secrets", "idp_id", idpID, "error", err)
			} else {
				var saved idp.Secrets
				if err := json.Unmarshal(plaintext, &saved); err != nil {
					h.logger.Debug("could not parse saved secrets", "idp_id", idpID, "error", err)
				} else {
					if secrets.ServiceAccountUsername == "" {
						secrets.ServiceAccountUsername = saved.ServiceAccountUsername
					}
					if secrets.ServiceAccountPassword == "" {
						secrets.ServiceAccountPassword = saved.ServiceAccountPassword
					}
					h.logger.Debug("loaded saved secrets for test connection",
						"idp_id", idpID,
						"has_username", secrets.ServiceAccountUsername != "",
						"has_password", secrets.ServiceAccountPassword != "",
					)
				}
			}
		}
	}

	if secrets.ServiceAccountUsername == "" || secrets.ServiceAccountPassword == "" {
		msg := "Service account credentials are required"
		if idpID != "" && secrets.ServiceAccountPassword == "" {
			msg = "Saved password is empty — re-enter the service account password and save the provider first"
		}
		h.renderer.JSON(w, http.StatusBadRequest, map[string]string{
			"status":  "error",
			"message": msg,
		})
		return
	}
	if providerType == "" {
		providerType = string(idp.ProviderTypeAD)
	}

	provider, err := buildProvider("_test", providerType, cfg, secrets, h.logger)
	if err != nil {
		h.renderer.JSON(w, http.StatusInternalServerError, map[string]string{
			"status":  "error",
			"message": "Failed to create provider: " + err.Error(),
		})
		return
	}

	testErr := provider.TestConnection(r.Context())

	if testErr != nil {
		h.logger.Debug("TestConnectionFromForm failed",
			"endpoint", cfg.Endpoint,
			"error", testErr,
		)
		h.renderer.JSON(w, http.StatusOK, map[string]string{
			"status":  "error",
			"message": testErr.Error(),
		})
		return
	}

	h.logger.Debug("TestConnectionFromForm successful",
		"endpoint", cfg.Endpoint,
	)
	h.renderer.JSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "Connection successful",
	})
}

// getLDAPConn loads an IDP record, decrypts secrets, connects, and binds.
func (h *AdminIDPHandler) getLDAPConn(ctx context.Context, idpID string) (idp.LDAPConn, *idp.Config, error) {
	record, err := h.store.GetIDP(ctx, idpID)
	if err != nil {
		return nil, nil, fmt.Errorf("loading IDP %s: %w", idpID, err)
	}

	var cfg idp.Config
	if err := json.Unmarshal([]byte(record.ConfigJSON), &cfg); err != nil {
		return nil, nil, fmt.Errorf("parsing config for %s: %w", idpID, err)
	}

	var secrets idp.Secrets
	if len(record.SecretBlob) > 0 {
		plaintext, err := h.crypto.Decrypt(record.SecretBlob)
		if err != nil {
			return nil, nil, fmt.Errorf("decrypting secrets for %s: %w", idpID, err)
		}
		if err := json.Unmarshal(plaintext, &secrets); err != nil {
			return nil, nil, fmt.Errorf("parsing secrets for %s: %w", idpID, err)
		}
	}

	conn, err := h.connector.Connect(ctx, cfg.Endpoint, cfg.Protocol, cfg.Timeout, cfg.TLSSkipVerify)
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to LDAP for %s: %w", idpID, err)
	}

	if err := conn.Bind(secrets.ServiceAccountUsername, secrets.ServiceAccountPassword); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("binding to LDAP for %s: %w", idpID, err)
	}

	return conn, &cfg, nil
}

// BrowseChildren returns the immediate children of a DN in the LDAP directory.
// GET /admin/idp/{id}/browse
func (h *AdminIDPHandler) BrowseChildren(w http.ResponseWriter, r *http.Request) {
	idpID := chi.URLParam(r, "id")
	dn := r.URL.Query().Get("dn")

	h.logger.Debug("BrowseChildren called", "idp_id", idpID, "dn", dn)

	conn, cfg, err := h.getLDAPConn(r.Context(), idpID)
	if err != nil {
		h.logger.Error("failed to get LDAP connection", "error", err, "idp_id", idpID)
		h.renderer.JSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to connect to directory: " + err.Error(),
		})
		return
	}
	defer conn.Close()

	if dn == "" {
		dn = cfg.BaseDN
	}

	h.logger.Debug("BrowseChildren searching", "idp_id", idpID, "base_dn", dn)

	searchReq := ldap.NewSearchRequest(
		dn,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"dn", "objectClass"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		h.logger.Error("LDAP search failed", "error", err, "idp_id", idpID, "dn", dn)
		h.renderer.JSON(w, http.StatusInternalServerError, map[string]string{
			"error": "LDAP search failed: " + err.Error(),
		})
		return
	}

	type childEntry struct {
		DN          string   `json:"dn"`
		Name        string   `json:"name"`
		ObjectClass []string `json:"object_class"`
	}

	children := make([]childEntry, 0, len(result.Entries))
	for _, entry := range result.Entries {
		// Extract RDN (first component of DN).
		name := entry.DN
		if parts := strings.SplitN(entry.DN, ",", 2); len(parts) > 0 {
			name = parts[0]
		}

		children = append(children, childEntry{
			DN:          entry.DN,
			Name:        name,
			ObjectClass: entry.GetAttributeValues("objectClass"),
		})
	}

	h.logger.Debug("BrowseChildren result", "idp_id", idpID, "dn", dn, "count", len(children))

	h.renderer.JSON(w, http.StatusOK, children)
}

// SearchDirectory searches the LDAP directory for entries matching an attribute filter.
// GET /admin/idp/{id}/search?attr=sAMAccountName&value=jhane
func (h *AdminIDPHandler) SearchDirectory(w http.ResponseWriter, r *http.Request) {
	idpID := chi.URLParam(r, "id")
	attr := r.URL.Query().Get("attr")
	value := r.URL.Query().Get("value")

	h.logger.Debug("SearchDirectory called", "idp_id", idpID, "attr", attr, "value", value)

	if attr == "" || value == "" {
		h.renderer.JSON(w, http.StatusBadRequest, map[string]string{
			"error": "attr and value query parameters are required",
		})
		return
	}

	conn, cfg, err := h.getLDAPConn(r.Context(), idpID)
	if err != nil {
		h.logger.Error("failed to get LDAP connection for search", "error", err, "idp_id", idpID)
		h.renderer.JSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to connect to directory: " + err.Error(),
		})
		return
	}
	defer conn.Close()

	searchBase := cfg.BaseDN
	filter := fmt.Sprintf("(%s=%s)", ldap.EscapeFilter(attr), ldap.EscapeFilter(value))

	h.logger.Debug("SearchDirectory LDAP search",
		"idp_id", idpID,
		"search_base", searchBase,
		"filter", filter,
	)

	searchReq := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		50, 0, false,
		filter,
		[]string{"dn", "objectClass"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		h.logger.Error("LDAP search failed", "error", err, "idp_id", idpID)
		h.renderer.JSON(w, http.StatusInternalServerError, map[string]string{
			"error": "LDAP search failed: " + err.Error(),
		})
		return
	}

	type searchResult struct {
		DN          string   `json:"dn"`
		ObjectClass []string `json:"object_class"`
	}

	results := make([]searchResult, 0, len(result.Entries))
	for _, entry := range result.Entries {
		results = append(results, searchResult{
			DN:          entry.DN,
			ObjectClass: entry.GetAttributeValues("objectClass"),
		})
	}

	h.logger.Debug("SearchDirectory results", "idp_id", idpID, "count", len(results))

	h.renderer.JSON(w, http.StatusOK, map[string]any{
		"results": results,
		"count":   len(results),
	})
}

// ReadEntry returns all attributes for a specific DN.
// GET /admin/idp/{id}/entry
func (h *AdminIDPHandler) ReadEntry(w http.ResponseWriter, r *http.Request) {
	idpID := chi.URLParam(r, "id")
	dn := r.URL.Query().Get("dn")

	h.logger.Debug("ReadEntry called", "idp_id", idpID, "dn", dn)

	if dn == "" {
		h.renderer.JSON(w, http.StatusBadRequest, map[string]string{
			"error": "dn query parameter is required",
		})
		return
	}

	conn, _, err := h.getLDAPConn(r.Context(), idpID)
	if err != nil {
		h.logger.Error("failed to get LDAP connection", "error", err, "idp_id", idpID)
		h.renderer.JSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to connect to directory: " + err.Error(),
		})
		return
	}
	defer conn.Close()

	searchReq := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"*"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		h.logger.Error("LDAP search failed", "error", err, "idp_id", idpID, "dn", dn)
		h.renderer.JSON(w, http.StatusInternalServerError, map[string]string{
			"error": "LDAP search failed: " + err.Error(),
		})
		return
	}

	if len(result.Entries) == 0 {
		h.renderer.JSON(w, http.StatusNotFound, map[string]string{
			"error": "Entry not found",
		})
		return
	}

	entry := result.Entries[0]

	type attrEntry struct {
		Name   string   `json:"name"`
		Values []string `json:"values"`
	}

	attrs := make([]attrEntry, 0, len(entry.Attributes))
	for _, a := range entry.Attributes {
		attrs = append(attrs, attrEntry{
			Name:   a.Name,
			Values: a.Values,
		})
	}

	sort.Slice(attrs, func(i, j int) bool {
		return strings.ToLower(attrs[i].Name) < strings.ToLower(attrs[j].Name)
	})

	h.logger.Debug("ReadEntry result", "idp_id", idpID, "dn", dn, "attr_count", len(attrs))

	h.renderer.JSON(w, http.StatusOK, map[string]any{
		"dn":         entry.DN,
		"attributes": attrs,
	})
}

// BrowsePage renders the LDAP directory browser page.
// GET /admin/idp/{id}/browse-page
func (h *AdminIDPHandler) BrowsePage(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	idpID := chi.URLParam(r, "id")

	record, err := h.store.GetIDP(r.Context(), idpID)
	if err != nil {
		h.logger.Error("failed to load IDP", "error", err, "idp_id", idpID)
		h.renderer.RenderError(w, r, http.StatusNotFound, "Identity provider not found")
		return
	}

	var cfg idp.Config
	if err := json.Unmarshal([]byte(record.ConfigJSON), &cfg); err != nil {
		h.logger.Error("failed to unmarshal IDP config", "error", err, "idp_id", idpID)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}

	h.renderer.Render(w, r, "admin_idp_browse.html", PageData{
		Title:     "Browse Directory - " + record.FriendlyName,
		Session:   sess,
		CSRFField: csrf.TemplateField(r),
		Data: map[string]any{
			"IDP":          record,
			"BaseDN":       cfg.BaseDN,
			"ProviderType": record.ProviderType,
			"ActivePage":   "idp",
		},
	})
}

// parseIDPConfig extracts IDP config fields from the form.
func (h *AdminIDPHandler) parseIDPConfig(r *http.Request) idp.Config {
	timeout, _ := strconv.Atoi(r.FormValue("timeout"))
	if timeout <= 0 {
		timeout = 10
	}
	retryCount, _ := strconv.Atoi(r.FormValue("retry_count"))
	if retryCount <= 0 {
		retryCount = 1
	}
	pwLength, _ := strconv.Atoi(r.FormValue("password_length"))
	if pwLength <= 0 {
		pwLength = 24
	}

	return idp.Config{
		Endpoint:                  r.FormValue("endpoint"),
		Protocol:                  r.FormValue("protocol"),
		BaseDN:                    r.FormValue("base_dn"),
		UserSearchBase:            r.FormValue("user_search_base"),
		GroupSearchBase:           r.FormValue("group_search_base"),
		Timeout:                   timeout,
		RetryCount:                retryCount,
		TLSSkipVerify:             r.FormValue("tls_skip_verify") == "on",
		PasswordComplexityHint:    r.FormValue("password_complexity_hint"),
		SendNotification:          r.FormValue("send_notification") == "on",
		NotificationEmailAttr:     r.FormValue("notification_email_attr"),
		PasswordAllowUppercase:    r.FormValue("password_allow_uppercase") == "on",
		PasswordAllowLowercase:    r.FormValue("password_allow_lowercase") == "on",
		PasswordAllowDigits:       r.FormValue("password_allow_digits") == "on",
		PasswordAllowSpecialChars: r.FormValue("password_allow_special") == "on",
		PasswordSpecialChars:      r.FormValue("password_special_chars"),
		PasswordLength:            pwLength,
	}
}

// parseAttributeMappings extracts attribute mappings from form arrays.
func (h *AdminIDPHandler) parseAttributeMappings(r *http.Request, idpID string) []db.AttributeMapping {
	canonicalNames := r.Form["canonical_name[]"]
	directoryAttrs := r.Form["directory_attr[]"]

	var mappings []db.AttributeMapping
	for i := 0; i < len(canonicalNames) && i < len(directoryAttrs); i++ {
		if canonicalNames[i] == "" || directoryAttrs[i] == "" {
			continue
		}
		mappings = append(mappings, db.AttributeMapping{
			IDPID:         idpID,
			CanonicalName: canonicalNames[i],
			DirectoryAttr: directoryAttrs[i],
		})
	}
	return mappings
}

// parseCorrelationRule extracts the correlation rule from the form.
// The target directory attribute is resolved at runtime from the target IDP's
// attribute mappings, so only the canonical attribute name is required.
func (h *AdminIDPHandler) parseCorrelationRule(r *http.Request, idpID string) *db.CorrelationRule {
	source := r.FormValue("source_canonical_attr")
	target := r.FormValue("target_directory_attr") // optional, for backward compat
	mode := r.FormValue("match_mode")

	if source == "" {
		return nil
	}
	if mode == "" {
		mode = "exact"
	}

	return &db.CorrelationRule{
		IDPID:               idpID,
		SourceCanonicalAttr: source,
		TargetDirectoryAttr: target,
		MatchMode:           mode,
	}
}

// encryptSecrets marshals and encrypts IDP secrets.
func (h *AdminIDPHandler) encryptSecrets(secrets idp.Secrets) ([]byte, error) {
	plaintext, err := json.Marshal(secrets)
	if err != nil {
		return nil, fmt.Errorf("marshaling secrets: %w", err)
	}
	blob, err := h.crypto.Encrypt(plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypting secrets: %w", err)
	}
	return blob, nil
}

// buildProvider creates a fully functional Provider from configuration.
func buildProvider(id, providerType string, cfg idp.Config, secrets idp.Secrets, logger *slog.Logger) (idp.Provider, error) {
	connector := &idp.DefaultLDAPConnector{}

	switch idp.ProviderType(providerType) {
	case idp.ProviderTypeAD:
		return ad.New(id, cfg, secrets, connector, logger), nil
	case idp.ProviderTypeFreeIPA:
		return freeipa.New(id, cfg, secrets, connector, logger), nil
	default:
		return nil, fmt.Errorf("unsupported provider type: %s", providerType)
	}
}

// registerProvider decrypts secrets and registers a live provider in the registry.
func (h *AdminIDPHandler) registerProvider(_ context.Context, record *db.IdentityProviderRecord) error {
	var cfg idp.Config
	if err := json.Unmarshal([]byte(record.ConfigJSON), &cfg); err != nil {
		return fmt.Errorf("parsing config for %s: %w", record.ID, err)
	}

	var secrets idp.Secrets
	if len(record.SecretBlob) > 0 {
		plaintext, err := h.crypto.Decrypt(record.SecretBlob)
		if err != nil {
			return fmt.Errorf("decrypting secrets for %s: %w", record.ID, err)
		}
		if err := json.Unmarshal(plaintext, &secrets); err != nil {
			return fmt.Errorf("parsing secrets for %s: %w", record.ID, err)
		}
	}

	provider, err := buildProvider(record.ID, record.ProviderType, cfg, secrets, h.logger)
	if err != nil {
		return fmt.Errorf("building provider %s: %w", record.ID, err)
	}

	h.registry.Register(record.ID, provider)
	h.logger.Info("provider registered in registry",
		"idp_id", record.ID,
		"type", record.ProviderType,
		"endpoint", cfg.Endpoint,
	)
	return nil
}

// LoadProviders loads all enabled IDPs from the database and registers them.
// Called once at startup.
func (h *AdminIDPHandler) LoadProviders(ctx context.Context) error {
	idps, err := h.store.ListEnabledIDPs(ctx)
	if err != nil {
		return fmt.Errorf("listing enabled IDPs: %w", err)
	}

	h.logger.Info("loading identity providers", "count", len(idps))

	for i := range idps {
		if err := h.registerProvider(ctx, &idps[i]); err != nil {
			h.logger.Error("failed to register provider at startup", "idp_id", idps[i].ID, "error", err)
			// Continue loading others.
		}
	}
	return nil
}
