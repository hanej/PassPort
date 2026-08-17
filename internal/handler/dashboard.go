package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
)

// IDPPanel holds the data needed to render a single IDP panel on the dashboard.
type IDPPanel struct {
	IDP            db.IdentityProviderRecord
	Mapping        *db.UserIDPMapping
	Config         *idp.Config
	DisplayName    string              // display_name fetched from target directory (best-effort)
	TargetUsername string              // username from the account mapping
	Email          string              // email fetched from target directory (best-effort)
	Warning        string              // correlation warning message (e.g. ambiguous match)
	PasswordPolicy *idp.PasswordPolicy // directory rules for the change form; nil when unknown
}

// IDPLink holds the data needed to render a weblink provider on the dashboard.
type IDPLink struct {
	IDP db.IdentityProviderRecord
	URL string
}

// DashboardSection is one group of providers on the dashboard. Group is nil for
// ungrouped providers, which render without a heading after all the groups.
type DashboardSection struct {
	Group  *db.IDPGroup
	Panels []IDPPanel
	Links  []IDPLink
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
	crypto     *crypto.Service
}

// NewDashboardHandler creates a new DashboardHandler.
func NewDashboardHandler(
	store db.Store,
	sessions *auth.SessionManager,
	registry *idp.Registry,
	correlator CorrelatorInterface,
	cryptoSvc *crypto.Service,
	renderer *Renderer,
	auditLogger *audit.Logger,
	logger *slog.Logger,
) *DashboardHandler {
	return &DashboardHandler{
		store:      store,
		crypto:     cryptoSvc,
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

	// A group failure must not take down the dashboard, so fall back to
	// rendering every provider ungrouped.
	groups, err := h.store.ListIDPGroups(r.Context())
	if err != nil {
		h.logger.Warn("failed to list provider groups, rendering ungrouped", "error", err)
		groups = nil
	}

	// Load the user's mappings from all IDPs.
	// Use empty authProviderID to retrieve mappings regardless of which provider
	// originally created them — consistent with how correlation determines linkage.
	var mappings []db.UserIDPMapping
	if sess.ProviderID != "" || sess.UserType == "local" {
		mappings, err = h.store.ListMappings(r.Context(), "", sess.Username)
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
	sections := make([]DashboardSection, 0, len(idps))
	allPanels := make([]IDPPanel, 0, len(idps))
	for _, sec := range sectionIDPs(groups, idps) {
		panels := make([]IDPPanel, 0, len(sec.IDPs))
		links := make([]IDPLink, 0)
		for _, rec := range sec.IDPs {
			// Weblink providers are not password-managed; render them as links.
			if !idp.ProviderType(rec.ProviderType).IsDirectory() {
				var cfg idp.Config
				if err := json.Unmarshal([]byte(rec.ConfigJSON), &cfg); err != nil {
					h.logger.Warn("failed to parse IDP config JSON", "idp_id", rec.ID, "error", err)
					continue
				}
				url := idp.NormalizeWebLinkURL(cfg.URL)
				if url == "" {
					continue
				}
				links = append(links, IDPLink{IDP: rec, URL: url})
				continue
			}

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

					// Best effort: the directory stays the authority, so an unreadable
					// policy just leaves the form without client-side rules.
					showPolicy := panel.Config == nil || !panel.Config.HideDiscoveredPasswordPolicy
					if reader, isReader := provider.(idp.PasswordPolicyReader); isReader && showPolicy {
						if dirPolicy, polErr := reader.ResolvePasswordPolicy(r.Context(), panel.Mapping.TargetAccountDN); polErr == nil {
							panel.PasswordPolicy = &dirPolicy
						} else {
							h.logger.Debug("could not read password policy for dashboard form",
								"idp_id", rec.ID, "error", polErr)
						}
					}
				}
			}

			panels = append(panels, panel)
		}

		// Dropping unusable weblinks can empty a section.
		if len(panels) == 0 && len(links) == 0 {
			continue
		}
		sections = append(sections, DashboardSection{Group: sec.Group, Panels: panels, Links: links})
		allPanels = append(allPanels, panels...)
	}

	h.logger.Debug("built dashboard panels",
		"panel_count", len(allPanels),
	)

	// Check if any panels are unlinked (for auto-refresh script).
	hasUnlinked := false
	for _, p := range allPanels {
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
			"Sections":    sections,
			"ProviderID":  sess.ProviderID,
			"HasUnlinked": hasUnlinked,
		},
	})
}

// ChangePassword processes a per-IDP password change request. It does not
// trigger MFA; the second factor, when required, is collected at login.
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
	// Use GetMappingForTarget (no auth_provider_id filter) so users with the same
	// username across multiple providers can still change their password even when
	// their mapping was created under a different provider than the one they are
	// currently logged in with.
	mapping, err := h.store.GetMappingForTarget(r.Context(), sess.Username, idpID)
	if err != nil {
		// Fall back to the strict lookup for local admins where auth_provider_id
		// matters (mapping key is "local").
		if authProvider == "local" {
			mapping, err = h.store.GetMapping(r.Context(), authProvider, sess.Username, idpID)
		}
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
		h.sessions.SetFlash(w, r, "error", "Password change failed: "+passwordChangeMessage(err))
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

	// Best-effort notification email. Failure here must not affect the
	// already-successful password change; sendPasswordEventEmail logs
	// everything it needs on its own.
	providerName := idpID
	if idpRecord, err := h.store.GetIDP(r.Context(), idpID); err == nil && idpRecord != nil {
		providerName = idpRecord.FriendlyName
	}
	userEmail, err := resolveNotificationEmailByDN(r.Context(), h.store, provider, idpID, mapping.TargetAccountDN)
	if err != nil {
		h.logger.Warn("could not resolve notification email address",
			"idp_id", idpID, "username", sess.Username, "error", err)
	}
	sendPasswordEventEmail(r.Context(), h.store, h.crypto, h.logger,
		"password_changed", idpID, providerName, sess.Username, userEmail, r.RemoteAddr)

	h.sessions.SetFlash(w, r, "success", "Password changed successfully")
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// passwordChangeMessage maps a provider error to a message that is safe to show
// an end user. Raw directory errors carry the endpoint, service account and
// target DNs, so they never reach the browser; callers log them instead.
func passwordChangeMessage(err error) string {
	switch {
	case errors.Is(err, idp.ErrPasswordPolicy):
		return "the new password does not meet your organization's complexity, history, or minimum age requirements."
	case strings.Contains(err.Error(), "current password is incorrect"):
		return "current password is incorrect."
	case errors.Is(err, idp.ErrAccountLocked):
		return "your account is locked. Please contact your IT administrator."
	case errors.Is(err, idp.ErrAccountDisabled):
		return "your account is disabled. Please contact your IT administrator."
	default:
		return "please try again or contact your administrator."
	}
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
		h.logger.Error("IDP status check: connection failed", "idp_id", idpID, "error", err)
		h.renderer.JSON(w, http.StatusOK, map[string]string{"status": "offline"})
		return
	}

	h.renderer.JSON(w, http.StatusOK, map[string]string{"status": "online"})
}

// IDPStatus returns the connection status for an identity provider as JSON.
// The underlying error is logged but never returned: it carries the directory
// endpoint and service account DN, which an ordinary user must not see.
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
		h.logger.Error("IDP status check: connection failed",
			"idp_id", idpID,
			"error", err,
		)
		h.renderer.JSON(w, http.StatusOK, map[string]string{
			"status": "offline",
			"error":  "connection failed",
		})
		return
	}

	h.logger.Debug("IDP status check: online", "idp_id", idpID)
	h.renderer.JSON(w, http.StatusOK, map[string]string{
		"status": "online",
	})
}
