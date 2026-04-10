package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
)

// IDPPanel holds the data needed to render a single IDP panel on the dashboard.
type IDPPanel struct {
	IDP            db.IdentityProviderRecord
	Mapping        *db.UserIDPMapping
	Config         *idp.Config
	DisplayName    string // display_name fetched from target directory (best-effort)
	TargetUsername string // username from the account mapping
	Email          string // email fetched from target directory (best-effort)
	Warning        string // correlation warning message (e.g. ambiguous match)
}

// DashboardHandler serves the user dashboard.
type DashboardHandler struct {
	store      db.Store
	sessions   *auth.SessionManager
	registry   *idp.Registry
	correlator CorrelatorInterface
	renderer   *Renderer
	audit      *audit.Logger
	logger     *slog.Logger
}

// NewDashboardHandler creates a new DashboardHandler.
func NewDashboardHandler(
	store db.Store,
	sessions *auth.SessionManager,
	registry *idp.Registry,
	correlator CorrelatorInterface,
	renderer *Renderer,
	auditLogger *audit.Logger,
	logger *slog.Logger,
) *DashboardHandler {
	return &DashboardHandler{
		store:      store,
		sessions:   sessions,
		registry:   registry,
		correlator: correlator,
		renderer:   renderer,
		audit:      auditLogger,
		logger:     logger,
	}
}

// ShowDashboard renders the user dashboard with IDP panels and account mappings.
// GET /dashboard
func (h *DashboardHandler) ShowDashboard(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("ShowDashboard called")

	sess := auth.SessionFromContext(r.Context())
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	idps, err := h.store.ListEnabledIDPs(r.Context())
	if err != nil {
		h.logger.Error("failed to list enabled IDPs", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}

	h.logger.Debug("loaded enabled IDPs",
		"count", len(idps),
	)

	// Load the user's mappings from all IDPs.
	var mappings []db.UserIDPMapping
	if sess.ProviderID != "" || sess.UserType == "local" {
		authProvider := sess.ProviderID
		if sess.UserType == "local" {
			authProvider = "local"
		}
		mappings, err = h.store.ListMappings(r.Context(), authProvider, sess.Username)
		if err != nil {
			h.logger.Error("failed to list user mappings", "error", err)
		}
	}

	h.logger.Debug("loaded user mappings",
		"count", len(mappings),
	)

	// Build a map of target_idp_id -> mapping for quick lookup.
	mappingByIDP := make(map[string]*db.UserIDPMapping, len(mappings))
	for i := range mappings {
		mappingByIDP[mappings[i].TargetIDPID] = &mappings[i]
	}

	// Load correlation warnings for this user.
	warnings, warnErr := h.store.ListCorrelationWarnings(r.Context(), sess.Username)
	if warnErr != nil {
		h.logger.Warn("failed to load correlation warnings", "error", warnErr)
	}
	warningByIDP := make(map[string]string, len(warnings))
	for _, w := range warnings {
		warningByIDP[w.TargetIDPID] = w.Message
	}

	// Build IDP panels.
	panels := make([]IDPPanel, 0, len(idps))
	for _, rec := range idps {
		panel := IDPPanel{
			IDP:     rec,
			Mapping: mappingByIDP[rec.ID],
			Warning: warningByIDP[rec.ID],
		}

		// Parse config JSON for password hints.
		if rec.ConfigJSON != "" {
			var cfg idp.Config
			if err := json.Unmarshal([]byte(rec.ConfigJSON), &cfg); err != nil {
				h.logger.Warn("failed to parse IDP config JSON",
					"idp_id", rec.ID,
					"error", err,
				)
			} else {
				panel.Config = &cfg
			}
		}

		// Populate username and best-effort display_name for linked accounts.
		if panel.Mapping != nil && panel.Mapping.TargetAccountDN != "" {
			panel.TargetUsername = panel.Mapping.AuthUsername

			if provider, ok := h.registry.Get(rec.ID); ok {
				attrMappings, mapErr := h.store.ListAttributeMappings(r.Context(), rec.ID)
				if mapErr == nil {
					for _, m := range attrMappings {
						switch m.CanonicalName {
						case "display_name":
							if val, attrErr := provider.GetUserAttribute(r.Context(), panel.Mapping.TargetAccountDN, m.DirectoryAttr); attrErr == nil {
								panel.DisplayName = val
							}
						case "email":
							if val, attrErr := provider.GetUserAttribute(r.Context(), panel.Mapping.TargetAccountDN, m.DirectoryAttr); attrErr == nil {
								panel.Email = val
							}
						}
					}
				}
			}
		}

		panels = append(panels, panel)
	}

	h.logger.Debug("built dashboard panels",
		"panel_count", len(panels),
	)

	// Check if any panels are unlinked (for auto-refresh script).
	hasUnlinked := false
	for _, p := range panels {
		if p.Mapping == nil {
			hasUnlinked = true
			break
		}
	}

	flash := h.sessions.GetFlash(r)

	h.renderer.Render(w, r, "dashboard.html", PageData{
		Title:   "Dashboard",
		Session: sess,
		Flash:   flash,
		Data: map[string]any{
			"Panels":      panels,
			"ProviderID":  sess.ProviderID,
			"HasUnlinked": hasUnlinked,
		},
	})
}

// ChangePassword processes a per-IDP password change request.
// If MFA is enabled and the session has not been recently verified via MFA,
// the user is redirected to the MFA flow first.
// POST /dashboard/change-password
func (h *DashboardHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	idpID := r.FormValue("idp_id")

	h.logger.Debug("ChangePassword called",
		"idp_id", idpID,
		"username", sess.Username,
	)

	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	if newPassword == "" {
		h.sessions.SetFlash(w, r, "error", "New password cannot be empty")
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	if newPassword != confirmPassword {
		h.sessions.SetFlash(w, r, "error", "New passwords do not match")
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	// Determine the auth provider for mapping lookup.
	authProvider := sess.ProviderID
	if sess.UserType == "local" {
		authProvider = "local"
	}

	// Verify the user has a mapping for this IDP.
	mapping, err := h.store.GetMapping(r.Context(), authProvider, sess.Username, idpID)
	if err != nil {
		h.logger.Warn("no mapping found for password change",
			"idp_id", idpID,
			"username", sess.Username,
			"error", err,
		)
		h.sessions.SetFlash(w, r, "error", "Account not linked to this identity provider")
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	// Get the provider from the registry.
	provider, ok := h.registry.Get(idpID)
	if !ok {
		h.sessions.SetFlash(w, r, "error", "Identity provider not available")
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	h.logger.Debug("calling provider ChangePassword",
		"idp_id", idpID,
		"target_dn", mapping.TargetAccountDN,
	)

	// Change the password via the provider.
	if err := provider.ChangePassword(r.Context(), mapping.TargetAccountDN, currentPassword, newPassword); err != nil {
		h.audit.Log(r.Context(), &db.AuditEntry{
			Timestamp:  time.Now().UTC(),
			Username:   sess.Username,
			SourceIP:   r.RemoteAddr,
			Action:     audit.ActionPasswordChange,
			ProviderID: idpID,
			Result:     audit.ResultFailure,
			Details:    err.Error(),
		})
		errMsg := sanitizeDN(err.Error(), mapping.TargetAccountDN, sess.Username)
		h.sessions.SetFlash(w, r, "error", "Password change failed: "+errMsg)
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	h.logger.Debug("password changed successfully",
		"idp_id", idpID,
		"username", sess.Username,
	)

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp:  time.Now().UTC(),
		Username:   sess.Username,
		SourceIP:   r.RemoteAddr,
		Action:     audit.ActionPasswordChange,
		ProviderID: idpID,
		Result:     audit.ResultSuccess,
		Details:    "Password changed successfully",
	})

	h.sessions.SetFlash(w, r, "success", "Password changed successfully")
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// PublicIDPStatus returns only online/offline for an IDP. No error details are
// exposed since this endpoint is available to unauthenticated users.
// GET /idp-status/{id}
func (h *DashboardHandler) PublicIDPStatus(w http.ResponseWriter, r *http.Request) {
	idpID := chi.URLParam(r, "id")
	if idpID == "" {
		h.renderer.JSON(w, http.StatusBadRequest, map[string]string{"status": "offline"})
		return
	}

	provider, ok := h.registry.Get(idpID)
	if !ok {
		h.renderer.JSON(w, http.StatusOK, map[string]string{"status": "offline"})
		return
	}

	if err := provider.TestConnection(r.Context()); err != nil {
		h.logger.Debug("IDP status check: connection failed", "idp_id", idpID, "error", err)
		h.renderer.JSON(w, http.StatusOK, map[string]string{"status": "offline"})
		return
	}

	h.renderer.JSON(w, http.StatusOK, map[string]string{"status": "online"})
}

// IDPStatus returns the connection status for an identity provider as JSON,
// including error details for authenticated users.
// GET /dashboard/idp-status/{id}
func (h *DashboardHandler) IDPStatus(w http.ResponseWriter, r *http.Request) {
	idpID := chi.URLParam(r, "id")
	if idpID == "" {
		h.renderer.JSON(w, http.StatusBadRequest, map[string]string{
			"status": "error",
			"error":  "missing IDP ID",
		})
		return
	}

	provider, ok := h.registry.Get(idpID)
	if !ok {
		h.logger.Debug("IDP status check: provider not in registry",
			"idp_id", idpID,
			"registered_count", len(h.registry.List()),
		)
		h.renderer.JSON(w, http.StatusNotFound, map[string]string{
			"status": "offline",
			"error":  "provider not registered",
		})
		return
	}

	if err := provider.TestConnection(r.Context()); err != nil {
		h.logger.Debug("IDP status check: connection failed",
			"idp_id", idpID,
			"error", err,
		)
		h.renderer.JSON(w, http.StatusOK, map[string]string{
			"status": "offline",
			"error":  err.Error(),
		})
		return
	}

	h.logger.Debug("IDP status check: online", "idp_id", idpID)
	h.renderer.JSON(w, http.StatusOK, map[string]string{
		"status": "online",
	})
}
