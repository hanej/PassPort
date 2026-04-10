package handler

import (
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
)

const mappingPageSize = 25

// AdminMappingsHandler handles user-IDP mapping management in the admin UI.
type AdminMappingsHandler struct {
	store    db.Store
	registry *idp.Registry
	renderer *Renderer
	audit    *audit.Logger
	logger   *slog.Logger
}

// NewAdminMappingsHandler creates a new AdminMappingsHandler.
func NewAdminMappingsHandler(
	store db.Store,
	registry *idp.Registry,
	renderer *Renderer,
	auditLogger *audit.Logger,
	logger *slog.Logger,
) *AdminMappingsHandler {
	return &AdminMappingsHandler{
		store:    store,
		registry: registry,
		renderer: renderer,
		audit:    auditLogger,
		logger:   logger,
	}
}

// Show renders the user mappings management page.
// GET /admin/mappings
func (h *AdminMappingsHandler) Show(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Show mappings page called")

	sess := auth.SessionFromContext(r.Context())

	idps, err := h.store.ListIDPs(r.Context())
	if err != nil {
		h.logger.Error("failed to list IDPs for mappings page", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to load identity providers")
		return
	}

	h.renderer.Render(w, r, "admin_mappings.html", PageData{
		Title:   "User Mappings",
		Session: sess,
		Data: map[string]any{
			"IDPs":       idps,
			"ActivePage": "mappings",
		},
	})
}

// Search lists mappings, optionally filtered by username and/or provider.
// An empty or missing username lists all mappings (pagination still applies).
// GET /admin/mappings/search
func (h *AdminMappingsHandler) Search(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	username := r.URL.Query().Get("username")
	authProviderID := r.URL.Query().Get("auth_provider_id")

	idps, err := h.store.ListIDPs(r.Context())
	if err != nil {
		h.logger.Error("failed to list IDPs", "error", err)
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	// Empty username means list-all; convert to "*" so SearchMappings uses LIKE '%'.
	searchUsername := username
	if searchUsername == "" {
		searchUsername = "*"
	}

	filter := db.MappingSearchFilter{
		ProviderID: authProviderID,
		Username:   searchUsername,
		Limit:      mappingPageSize,
		Offset:     (page - 1) * mappingPageSize,
	}

	h.logger.Debug("searching mappings",
		"username", username,
		"auth_provider_id", authProviderID,
		"page", page,
	)

	mappings, totalCount, err := h.store.SearchMappings(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to search mappings", "error", err, "username", username)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to search mappings")
		return
	}

	totalPages := int(math.Ceil(float64(totalCount) / float64(mappingPageSize)))
	if totalPages < 1 {
		totalPages = 1
	}

	// Build base URL for pagination links, preserving filter params.
	q := r.URL.Query()
	q.Del("page")
	qs := q.Encode()
	var paginationBase string
	if qs != "" {
		paginationBase = "/admin/mappings/search?" + qs + "&page="
	} else {
		paginationBase = "/admin/mappings/search?page="
	}

	h.logger.Debug("mappings search complete",
		"username", username,
		"provider_id", authProviderID,
		"result_count", len(mappings),
		"total_count", totalCount,
	)

	// Directory lookup only makes sense for an exact username (no wildcards, not empty).
	isWildcard := username == "" || strings.Contains(username, "*")
	var directoryDN string
	var directoryErr string
	if !isWildcard && authProviderID != "" && authProviderID != "local" {
		provider, ok := h.registry.Get(authProviderID)
		if !ok {
			h.logger.Debug("directory lookup skipped: provider not in registry", "provider_id", authProviderID)
			directoryErr = "Provider not available in registry"
		} else {
			h.logger.Debug("searching directory for user", "provider_id", authProviderID, "username", username)
			dn, err := provider.SearchUser(r.Context(), "uid", username)
			if err != nil {
				h.logger.Debug("directory user search failed", "provider_id", authProviderID, "username", username, "error", err)
				// Try sAMAccountName for AD.
				dn, err = provider.SearchUser(r.Context(), "sAMAccountName", username)
			}
			if err != nil {
				directoryErr = "User not found in directory: " + err.Error()
			} else {
				directoryDN = dn
				h.logger.Debug("directory user found", "provider_id", authProviderID, "username", username, "dn", dn)
			}
		}
	}

	h.renderer.Render(w, r, "admin_mappings.html", PageData{
		Title:   "User Mappings",
		Session: sess,
		Data: map[string]any{
			"IDPs":           idps,
			"Mappings":       mappings,
			"SearchUsername": username,
			"SearchProvider": authProviderID,
			"DirectoryDN":    directoryDN,
			"DirectoryError": directoryErr,
			"IsWildcard":     isWildcard,
			"HasSearched":    true,
			"TotalCount":     totalCount,
			"CurrentPage":    page,
			"TotalPages":     totalPages,
			"PaginationBase": paginationBase,
			"ActivePage":     "mappings",
		},
	})
}

// Delete removes a single user-IDP mapping.
// POST /admin/mappings/{id}/delete
func (h *AdminMappingsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	idStr := chi.URLParam(r, "id")

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		h.renderer.RenderError(w, r, http.StatusBadRequest, "Invalid mapping ID")
		return
	}

	h.logger.Debug("Delete mapping called",
		"mapping_id", id,
	)

	if err := h.store.DeleteMapping(r.Context(), id); err != nil {
		h.logger.Error("failed to delete mapping", "error", err, "mapping_id", id)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to delete mapping")
		return
	}

	h.logger.Debug("mapping deleted successfully",
		"mapping_id", id,
	)

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp: time.Now().UTC(),
		Username:  sess.Username,
		SourceIP:  r.RemoteAddr,
		Action:    audit.ActionMappingReset,
		Result:    audit.ResultSuccess,
		Details:   fmt.Sprintf("Deleted mapping ID %d", id),
	})

	http.Redirect(w, r, "/admin/mappings", http.StatusFound)
}

// DeleteAll removes all mappings for a user.
// POST /admin/mappings/delete-all
func (h *AdminMappingsHandler) DeleteAll(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	if err := r.ParseForm(); err != nil {
		h.renderer.RenderError(w, r, http.StatusBadRequest, "Invalid form data")
		return
	}

	authProviderID := r.FormValue("auth_provider_id")
	username := r.FormValue("username")

	h.logger.Debug("DeleteAll mappings called",
		"username", username,
		"auth_provider_id", authProviderID,
	)

	if username == "" {
		h.renderer.RenderError(w, r, http.StatusBadRequest, "Username is required")
		return
	}

	count, err := h.store.DeleteAllMappings(r.Context(), authProviderID, username)
	if err != nil {
		h.logger.Error("failed to delete all mappings", "error", err, "username", username)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to delete mappings")
		return
	}

	h.logger.Debug("all mappings deleted",
		"username", username,
		"auth_provider_id", authProviderID,
		"count_deleted", count,
	)

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp: time.Now().UTC(),
		Username:  sess.Username,
		SourceIP:  r.RemoteAddr,
		Action:    audit.ActionMappingResetAll,
		Result:    audit.ResultSuccess,
		Details:   fmt.Sprintf("Deleted %d mappings for user %q (provider=%s)", count, username, authProviderID),
	})

	http.Redirect(w, r, "/admin/mappings", http.StatusFound)
}
