package handler

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
)

// LinkHandler serves manual IDP account linking.
type LinkHandler struct {
	store    db.Store
	sessions *auth.SessionManager
	registry *idp.Registry
	renderer *Renderer
	audit    *audit.Logger
	logger   *slog.Logger
}

// NewLinkHandler creates a new LinkHandler.
func NewLinkHandler(
	store db.Store,
	sessions *auth.SessionManager,
	registry *idp.Registry,
	renderer *Renderer,
	auditLogger *audit.Logger,
	logger *slog.Logger,
) *LinkHandler {
	return &LinkHandler{
		store:    store,
		sessions: sessions,
		registry: registry,
		renderer: renderer,
		audit:    auditLogger,
		logger:   logger,
	}
}

// LinkAccount processes a manual account linking request. The user provides
// credentials for a target IDP, which are verified via Authenticate before
// the mapping is created.
// POST /dashboard/link-account
func (h *LinkHandler) LinkAccount(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Local admin accounts cannot link to external IDPs.
	if sess.UserType == "local" {
		h.logger.Warn("local admin attempted to link IDP account", "username", sess.Username)
		h.sessions.SetFlash(w, r, "error", "Local admin accounts cannot be linked to identity providers")
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	idpID := strings.TrimSpace(r.FormValue("idp_id"))
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	if idpID == "" || username == "" || password == "" {
		h.sessions.SetFlash(w, r, "error", "All fields are required")
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	provider, ok := h.registry.Get(idpID)
	if !ok {
		h.logger.Warn("link failed: provider not in registry",
			"idp_id", idpID,
			"username", sess.Username,
			"registered_count", len(h.registry.List()),
		)
		h.sessions.SetFlash(w, r, "error", "Identity provider not available")
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	h.logger.Debug("linking account",
		"idp_id", idpID,
		"target_username", username,
		"session_user", sess.Username,
	)

	// Verify the credentials against the target IDP.
	if err := provider.Authenticate(r.Context(), username, password); err != nil {
		h.audit.Log(r.Context(), &db.AuditEntry{
			Timestamp:  time.Now().UTC(),
			Username:   sess.Username,
			SourceIP:   r.RemoteAddr,
			Action:     audit.ActionLinkFailed,
			ProviderID: idpID,
			Result:     audit.ResultFailure,
			Details:    fmt.Sprintf("manual link authentication failed: %v", err),
		})
		errMsg := "Authentication failed for the target account"
		if strings.Contains(err.Error(), "user not found") || strings.Contains(err.Error(), "could not resolve user") {
			errMsg = "User not found in the target directory — check the User Search Base in the provider config"
		}
		h.sessions.SetFlash(w, r, "error", errMsg)
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	h.logger.Debug("link account auth successful",
		"idp_id", idpID,
		"target_username", username,
		"session_user", sess.Username,
	)

	// Prevent duplicate links: if any auth provider already has a mapping to
	// this target IDP for the user, skip creating another one.
	if exists, _ := h.store.HasMappingToTarget(r.Context(), sess.Username, idpID); exists {
		h.logger.Warn("manual link skipped: mapping to target already exists",
			"idp_id", idpID,
			"username", sess.Username,
		)
		h.sessions.SetFlash(w, r, "error", "Your account is already linked to this identity provider")
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	// Determine the auth provider for the mapping.
	authProvider := sess.ProviderID
	if sess.UserType == "local" {
		authProvider = "local"
	}

	now := time.Now().UTC()
	mapping := &db.UserIDPMapping{
		AuthProviderID:  authProvider,
		AuthUsername:    sess.Username,
		TargetIDPID:     idpID,
		TargetAccountDN: username,
		LinkType:        "manual",
		LinkedAt:        now,
		VerifiedAt:      &now,
	}

	if err := h.store.UpsertMapping(r.Context(), mapping); err != nil {
		h.logger.Error("failed to create manual mapping",
			"error", err,
			"idp_id", idpID,
			"username", sess.Username,
		)
		h.audit.Log(r.Context(), &db.AuditEntry{
			Timestamp:  time.Now().UTC(),
			Username:   sess.Username,
			SourceIP:   r.RemoteAddr,
			Action:     audit.ActionLinkFailed,
			ProviderID: idpID,
			Result:     audit.ResultFailure,
			Details:    fmt.Sprintf("failed to save manual link: %v", err),
		})
		h.sessions.SetFlash(w, r, "error", "Failed to link account")
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	// Clear any correlation ambiguity warning now that the user linked manually.
	if err := h.store.DeleteCorrelationWarning(r.Context(), sess.Username, idpID); err != nil {
		h.logger.Warn("failed to clear correlation warning after manual link",
			"error", err,
			"idp_id", idpID,
			"username", sess.Username,
		)
	}

	h.logger.Debug("mapping created for linked account",
		"idp_id", idpID,
		"session_user", sess.Username,
		"target_username", username,
	)

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp:  time.Now().UTC(),
		Username:   sess.Username,
		SourceIP:   r.RemoteAddr,
		Action:     audit.ActionLinkManual,
		ProviderID: idpID,
		Result:     audit.ResultSuccess,
		Details:    fmt.Sprintf("manually linked to %s as %s", idpID, username),
	})

	h.sessions.SetFlash(w, r, "success", "Account linked successfully")
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}
