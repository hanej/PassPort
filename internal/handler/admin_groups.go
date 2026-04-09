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
	"github.com/gorilla/csrf"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
)

// AdminGroupsHandler handles admin group management in the admin UI.
type AdminGroupsHandler struct {
	store    db.Store
	registry *idp.Registry
	renderer *Renderer
	audit    *audit.Logger
	logger   *slog.Logger
}

// NewAdminGroupsHandler creates a new AdminGroupsHandler.
func NewAdminGroupsHandler(
	store db.Store,
	registry *idp.Registry,
	renderer *Renderer,
	auditLogger *audit.Logger,
	logger *slog.Logger,
) *AdminGroupsHandler {
	return &AdminGroupsHandler{
		store:    store,
		registry: registry,
		renderer: renderer,
		audit:    auditLogger,
		logger:   logger,
	}
}

// List renders the admin groups page with all groups and IDPs for the add form dropdown.
// GET /admin/groups
func (h *AdminGroupsHandler) List(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("List admin groups called")

	sess := auth.SessionFromContext(r.Context())

	groups, err := h.store.ListAdminGroups(r.Context())
	if err != nil {
		h.logger.Error("failed to list admin groups", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to load admin groups")
		return
	}

	idps, err := h.store.ListIDPs(r.Context())
	if err != nil {
		h.logger.Error("failed to list IDPs for group form", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to load identity providers")
		return
	}

	h.logger.Debug("admin groups and IDPs loaded",
		"group_count", len(groups),
		"idp_count", len(idps),
	)

	h.renderer.Render(w, r, "admin_groups.html", PageData{
		Title:     "Admin Groups",
		Session:   sess,
		CSRFField: csrf.TemplateField(r),
		Data: map[string]any{
			"Groups":     groups,
			"IDPs":       idps,
			"ActivePage": "groups",
		},
	})
}

// Create processes the admin group creation form.
// POST /admin/groups
func (h *AdminGroupsHandler) Create(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	if err := r.ParseForm(); err != nil {
		h.renderer.RenderError(w, r, http.StatusBadRequest, "Invalid form data")
		return
	}

	idpID := r.FormValue("idp_id")
	groupDN := r.FormValue("group_dn")
	description := r.FormValue("description")

	h.logger.Debug("Create admin group called",
		"idp_id", idpID,
		"group_dn", groupDN,
	)

	if idpID == "" || groupDN == "" {
		// Re-render with error.
		groups, _ := h.store.ListAdminGroups(r.Context())
		idps, _ := h.store.ListIDPs(r.Context())

		h.renderer.Render(w, r, "admin_groups.html", PageData{
			Title:     "Admin Groups",
			Session:   sess,
			CSRFField: csrf.TemplateField(r),
			Flash:     map[string]string{"category": "error", "message": "IDP and Group DN are required"},
			Data: map[string]any{
				"Groups": groups,
				"IDPs":   idps,
			},
		})
		return
	}

	group := &db.AdminGroup{
		IDPID:       idpID,
		GroupDN:     groupDN,
		Description: description,
	}

	if err := h.store.CreateAdminGroup(r.Context(), group); err != nil {
		h.logger.Error("failed to create admin group", "error", err)
		groups, _ := h.store.ListAdminGroups(r.Context())
		idps, _ := h.store.ListIDPs(r.Context())

		h.renderer.Render(w, r, "admin_groups.html", PageData{
			Title:     "Admin Groups",
			Session:   sess,
			CSRFField: csrf.TemplateField(r),
			Flash:     map[string]string{"category": "error", "message": "Failed to create admin group: " + err.Error()},
			Data: map[string]any{
				"Groups": groups,
				"IDPs":   idps,
			},
		})
		return
	}

	h.logger.Debug("admin group created successfully",
		"idp_id", idpID,
		"group_dn", groupDN,
	)

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp:  time.Now().UTC(),
		Username:   sess.Username,
		SourceIP:   r.RemoteAddr,
		Action:     audit.ActionAdminGroupAdd,
		ProviderID: idpID,
		Result:     audit.ResultSuccess,
		Details:    fmt.Sprintf("Added admin group %q for IDP %s", groupDN, idpID),
	})

	http.Redirect(w, r, "/admin/groups", http.StatusFound)
}

// Delete removes an admin group mapping.
// POST /admin/groups/{id}/delete
func (h *AdminGroupsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	idStr := chi.URLParam(r, "id")

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		h.renderer.RenderError(w, r, http.StatusBadRequest, "Invalid group ID")
		return
	}

	h.logger.Debug("Delete admin group called",
		"group_id", id,
	)

	if err := h.store.DeleteAdminGroup(r.Context(), id); err != nil {
		h.logger.Error("failed to delete admin group", "error", err, "group_id", id)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to delete admin group")
		return
	}

	h.logger.Debug("admin group deleted successfully",
		"group_id", id,
	)

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp: time.Now().UTC(),
		Username:  sess.Username,
		SourceIP:  r.RemoteAddr,
		Action:    audit.ActionAdminGroupDelete,
		Result:    audit.ResultSuccess,
		Details:   fmt.Sprintf("Deleted admin group ID %d", id),
	})

	http.Redirect(w, r, "/admin/groups", http.StatusFound)
}

// Members returns the members of an admin group as JSON.
// GET /admin/groups/{id}/members
func (h *AdminGroupsHandler) Members(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")

	h.logger.Debug("Members called",
		"group_id", idStr,
	)

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"status": "error", "message": "Invalid group ID"})
		return
	}

	// Look up the admin group to get the IDP ID and group DN.
	groups, err := h.store.ListAdminGroups(r.Context())
	if err != nil {
		h.logger.Error("failed to list admin groups", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"status": "error", "message": "Failed to load groups"})
		return
	}

	var group *db.AdminGroup
	for i := range groups {
		if groups[i].ID == id {
			group = &groups[i]
			break
		}
	}
	if group == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"status": "error", "message": "Group not found"})
		return
	}

	provider, ok := h.registry.Get(group.IDPID)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"status": "error", "message": "Provider not available"})
		return
	}

	members, err := provider.GetGroupMembers(r.Context(), group.GroupDN)
	if err != nil {
		h.logger.Error("failed to get group members", "error", err, "group_dn", group.GroupDN, "idp_id", group.IDPID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"status": "error", "message": "Failed to query group members: " + err.Error()})
		return
	}

	h.logger.Debug("group members retrieved",
		"group_id", id,
		"member_count", len(members),
	)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"members": members,
		"count":   len(members),
	})
}

// sanitizeDN strips full LDAP DNs from an error message, replacing them with
// a short label (typically the username). This prevents leaking internal directory
// structure to end users in flash messages.
func sanitizeDN(errMsg, dn, label string) string {
	if dn == "" {
		return errMsg
	}
	return strings.ReplaceAll(errMsg, dn, label)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
