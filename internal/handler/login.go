package handler

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/csrf"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
)

// CorrelatorInterface abstracts the correlation engine so the login handler
// can trigger user-to-IDP correlation without depending on the full engine.
type CorrelatorInterface interface {
	CorrelateUser(ctx context.Context, authProviderID, authUsername string) error
}

// LoginHandler serves the login and logout pages.
type LoginHandler struct {
	store      db.Store
	sessions   *auth.SessionManager
	registry   *idp.Registry
	correlator CorrelatorInterface
	crypto     *crypto.Service
	renderer   *Renderer
	audit      *audit.Logger
	logger     *slog.Logger
}

// NewLoginHandler creates a new LoginHandler.
func NewLoginHandler(
	store db.Store,
	sessions *auth.SessionManager,
	registry *idp.Registry,
	correlator CorrelatorInterface,
	cryptoSvc *crypto.Service,
	renderer *Renderer,
	auditLogger *audit.Logger,
	logger *slog.Logger,
) *LoginHandler {
	return &LoginHandler{
		store:      store,
		sessions:   sessions,
		registry:   registry,
		correlator: correlator,
		crypto:     cryptoSvc,
		renderer:   renderer,
		audit:      auditLogger,
		logger:     logger,
	}
}

// ShowLogin renders the login page with the list of enabled identity providers.
// GET /login
func (h *LoginHandler) ShowLogin(w http.ResponseWriter, r *http.Request) {
	idps, err := h.store.ListEnabledIDPs(r.Context())
	if err != nil {
		h.logger.Error("failed to list enabled IDPs", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}

	h.logger.Debug("ShowLogin called",
		"idp_count", len(idps),
	)

	flash := h.sessions.GetFlash(r)

	h.renderer.Render(w, r, "login.html", PageData{
		Title:     "Login",
		CSRFField: csrf.TemplateField(r),
		Flash:     flash,
		Data: map[string]any{
			"IDPs": idps,
		},
	})
}

// Login processes the login form submission.
// POST /login
func (h *LoginHandler) Login(w http.ResponseWriter, r *http.Request) {
	providerID := strings.TrimSpace(r.FormValue("provider_id"))
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	if username == "" || password == "" {
		h.renderLoginError(w, r, "Username and password are required")
		return
	}

	if providerID == "local" {
		h.loginLocal(w, r, username, password)
		return
	}

	h.loginProvider(w, r, providerID, username, password)
}

// loginLocal authenticates against the local admin account.
func (h *LoginHandler) loginLocal(w http.ResponseWriter, r *http.Request, username, password string) {
	h.logger.Debug("loginLocal called",
		"username", username,
	)

	admin, err := h.store.GetLocalAdmin(r.Context(), username)
	if err != nil {
		h.auditLoginFailure(r, "local", username, "unknown user")
		h.renderLoginError(w, r, "Invalid username or password")
		return
	}

	if err := auth.CheckPassword(admin.PasswordHash, password); err != nil {
		h.auditLoginFailure(r, "local", username, "invalid password")
		h.renderLoginError(w, r, "Invalid username or password")
		return
	}

	_, err = h.sessions.CreateSession(w, r, "local", "", username, true, admin.MustChangePassword)
	if err != nil {
		h.logger.Error("failed to create session", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}

	h.logger.Debug("local auth successful",
		"username", username,
	)

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp: time.Now().UTC(),
		Username:  username,
		SourceIP:  r.RemoteAddr,
		Action:    audit.ActionLogin,
		Result:    audit.ResultSuccess,
		Details:   "Local admin login",
	})

	if admin.MustChangePassword {
		http.Redirect(w, r, "/change-password", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// loginProvider authenticates against an external identity provider.
func (h *LoginHandler) loginProvider(w http.ResponseWriter, r *http.Request, providerID, username, password string) {
	h.logger.Debug("attempting IDP login",
		"provider_id", providerID,
		"username", username,
		"ip", r.RemoteAddr,
	)

	provider, ok := h.registry.Get(providerID)
	if !ok {
		h.logger.Warn("login failed: provider not in registry",
			"provider_id", providerID,
			"registered_count", len(h.registry.List()),
		)
		h.renderLoginError(w, r, "Identity provider not available")
		return
	}

	h.logger.Debug("authenticating user against provider",
		"provider_id", providerID,
		"provider_type", provider.Type(),
		"username", username,
	)

	if err := provider.Authenticate(r.Context(), username, password); err != nil {
		h.logger.Debug("authentication failed",
			"provider_id", providerID,
			"username", username,
			"error", err,
		)
		h.auditLoginFailure(r, providerID, username, fmt.Sprintf("authentication failed: %v", err))
		h.renderLoginError(w, r, "Invalid username or password")
		return
	}

	h.logger.Debug("authentication successful, checking admin group membership",
		"provider_id", providerID,
		"username", username,
	)

	// Determine if the user is an admin by checking group membership.
	isAdmin := h.checkAdminGroupMembership(r.Context(), provider, providerID, username)

	h.logger.Debug("creating session",
		"provider_id", providerID,
		"username", username,
		"is_admin", isAdmin,
	)

	newSessionID, err := h.sessions.CreateSession(w, r, "provider", providerID, username, isAdmin, false)
	if err != nil {
		h.logger.Error("failed to create session", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Internal server error")
		return
	}

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp:  time.Now().UTC(),
		Username:   username,
		SourceIP:   r.RemoteAddr,
		Action:     audit.ActionLogin,
		ProviderID: providerID,
		Result:     audit.ResultSuccess,
		Details:    "IDP login",
	})

	// Check if MFA on login is required for IDP users.
	mfaRedirect := h.shouldEnforceMFAOnLogin(r.Context(), providerID)
	if mfaRedirect && newSessionID != "" {
		if err := h.store.UpdateSessionMFA(r.Context(), newSessionID, true, ""); err != nil {
			h.logger.Error("failed to set MFA pending on session", "error", err)
			// Fall through to dashboard on error (fail open).
		} else {
			h.logger.Info("MFA required on login, redirecting to /mfa",
				"username", username,
				"provider_id", providerID,
			)
			http.Redirect(w, r, "/mfa", http.StatusFound)
			return
		}
	}

	// Create a self-mapping synchronously so it's visible on the first
	// dashboard render. Try uid first (FreeIPA), then sAMAccountName (AD).
	dn, dnErr := provider.SearchUser(r.Context(), "uid", username)
	if dnErr != nil {
		dn, dnErr = provider.SearchUser(r.Context(), "sAMAccountName", username)
	}
	if dnErr != nil {
		h.logger.Debug("could not resolve user DN for self-mapping",
			"provider_id", providerID,
			"username", username,
			"error", dnErr,
		)
	} else {
		// Only create self-mapping if no mapping to this IDP already exists.
		exists, _ := h.store.HasMappingToTarget(r.Context(), username, providerID)
		if exists {
			h.logger.Debug("self-mapping skipped, mapping to target already exists",
				"provider_id", providerID,
				"username", username,
			)
		} else {
			now := time.Now().UTC()
			mapping := &db.UserIDPMapping{
				AuthProviderID:  providerID,
				AuthUsername:    username,
				TargetIDPID:     providerID,
				TargetAccountDN: dn,
				LinkType:        "auto",
				LinkedAt:        now,
				VerifiedAt:      &now,
			}
			if err := h.store.UpsertMapping(r.Context(), mapping); err != nil {
				h.logger.Warn("failed to create self-mapping",
					"provider_id", providerID,
					"username", username,
					"error", err,
				)
			} else {
				h.logger.Debug("self-mapping created",
					"provider_id", providerID,
					"username", username,
					"target_dn", dn,
				)
			}
		}
	}

	// Run correlation for cross-IDP mappings in the background, but only if
	// there are IDPs without an existing mapping. If we cannot determine this
	// (e.g. a DB error), default to running correlation.
	if h.correlator != nil {
		runCorrelation := true
		enabledIDPs, idpErr := h.store.ListEnabledIDPs(r.Context())
		existingMappings, mapErr := h.store.ListMappings(r.Context(), providerID, username)
		if idpErr == nil && mapErr == nil {
			linked := make(map[string]struct{}, len(existingMappings))
			for _, m := range existingMappings {
				linked[m.TargetIDPID] = struct{}{}
			}
			runCorrelation = false
			for _, rec := range enabledIDPs {
				if _, ok := linked[rec.ID]; !ok {
					runCorrelation = true
					break
				}
			}
		}
		if runCorrelation {
			go func() {
				if err := h.correlator.CorrelateUser(context.Background(), providerID, username); err != nil {
					h.logger.Warn("background correlation failed",
						"provider_id", providerID,
						"username", username,
						"error", err,
					)
				}
			}()
		} else {
			h.logger.Debug("correlation skipped, all IDPs already linked",
				"provider_id", providerID,
				"username", username,
			)
		}
	}

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// shouldEnforceMFAOnLogin checks whether the login should be gated by MFA.
// Returns true only when the setting is enabled, an MFA provider is configured
// for the IDP, and the provider is healthy. Fails open on any error.
func (h *LoginHandler) shouldEnforceMFAOnLogin(ctx context.Context, providerID string) bool {
	required, err := h.store.GetMFALoginRequired(ctx)
	if err != nil {
		h.logger.Warn("failed to check MFA login required setting, skipping MFA", "error", err)
		return false
	}
	if !required {
		return false
	}

	client, _, err := buildMFAClientForIDP(ctx, h.store, h.crypto, providerID, h.logger)
	if err != nil {
		h.logger.Warn("failed to build MFA client for login enforcement, skipping MFA",
			"provider_id", providerID, "error", err)
		return false
	}
	if client == nil {
		h.logger.Debug("no MFA provider configured for IDP, skipping login MFA",
			"provider_id", providerID)
		return false
	}

	if err := client.HealthCheck(ctx); err != nil {
		h.logger.Warn("MFA provider health check failed, allowing login without MFA (fail-open)",
			"provider_id", providerID, "error", err)
		return false
	}

	return true
}

// checkAdminGroupMembership checks whether the authenticated user belongs to
// any admin group configured for the given IDP.
func (h *LoginHandler) checkAdminGroupMembership(ctx context.Context, provider idp.Provider, providerID, username string) bool {
	adminGroups, err := h.store.GetAdminGroupsByIDP(ctx, providerID)
	if err != nil {
		h.logger.Warn("failed to load admin groups", "provider_id", providerID, "error", err)
		return false
	}
	if len(adminGroups) == 0 {
		h.logger.Debug("no admin groups configured for provider", "provider_id", providerID)
		return false
	}

	h.logger.Debug("checking admin group membership",
		"provider_id", providerID,
		"username", username,
		"admin_group_count", len(adminGroups),
	)

	userGroups, err := provider.GetUserGroups(ctx, username)
	if err != nil {
		h.logger.Warn("failed to get user groups", "provider_id", providerID, "username", username, "error", err)
		return false
	}

	h.logger.Debug("user group membership retrieved",
		"provider_id", providerID,
		"username", username,
		"user_group_count", len(userGroups),
	)

	// Build a lookup set of admin group DNs.
	adminDNs := make(map[string]struct{}, len(adminGroups))
	for _, ag := range adminGroups {
		adminDNs[strings.ToLower(ag.GroupDN)] = struct{}{}
	}

	for _, ug := range userGroups {
		if _, ok := adminDNs[strings.ToLower(ug)]; ok {
			h.logger.Debug("admin group match found",
				"provider_id", providerID,
				"username", username,
				"matched_group", ug,
			)
			return true
		}
	}

	h.logger.Debug("no admin group match",
		"provider_id", providerID,
		"username", username,
	)
	return false
}

// Logout destroys the current session and redirects to /login.
// GET /logout
func (h *LoginHandler) Logout(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	if sess != nil {
		h.logger.Debug("Logout called",
			"username", sess.Username,
		)
	}

	if sess != nil {
		h.audit.Log(r.Context(), &db.AuditEntry{
			Timestamp:  time.Now().UTC(),
			Username:   sess.Username,
			SourceIP:   r.RemoteAddr,
			Action:     audit.ActionLogout,
			ProviderID: sess.ProviderID,
			Result:     audit.ResultSuccess,
			Details:    "User logged out",
		})
	}

	h.sessions.DestroySession(w, r)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// auditLoginFailure records a failed login attempt.
func (h *LoginHandler) auditLoginFailure(r *http.Request, providerID, username, details string) {
	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp:  time.Now().UTC(),
		Username:   username,
		SourceIP:   r.RemoteAddr,
		Action:     audit.ActionLogin,
		ProviderID: providerID,
		Result:     audit.ResultFailure,
		Details:    details,
	})
}

// renderLoginError re-renders the login page with an error message.
func (h *LoginHandler) renderLoginError(w http.ResponseWriter, r *http.Request, message string) {
	idps, err := h.store.ListEnabledIDPs(r.Context())
	if err != nil {
		h.logger.Error("failed to list enabled IDPs", "error", err)
	}

	h.renderer.Render(w, r, "login.html", PageData{
		Title:     "Login",
		CSRFField: csrf.TemplateField(r),
		Flash:     map[string]string{"category": "error", "message": message},
		Data: map[string]any{
			"IDPs": idps,
		},
	})
}
