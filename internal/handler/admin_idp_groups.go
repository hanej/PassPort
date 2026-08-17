package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/db"
)

// maxGroupNameLen bounds the group name so it cannot break the page layout.
const maxGroupNameLen = 60

// AdminIDPGroupHandler manages provider groups and the arrangement of
// identity providers within them.
type AdminIDPGroupHandler struct {
	store    db.Store
	renderer *Renderer
	audit    *audit.Logger
	logger   *slog.Logger
}

// NewAdminIDPGroupHandler creates a new AdminIDPGroupHandler.
func NewAdminIDPGroupHandler(
	store db.Store,
	renderer *Renderer,
	auditLogger *audit.Logger,
	logger *slog.Logger,
) *AdminIDPGroupHandler {
	return &AdminIDPGroupHandler{
		store:    store,
		renderer: renderer,
		audit:    auditLogger,
		logger:   logger,
	}
}

// GroupArrangement is the view model for one group column on the arrangement
// page. Group is nil for the ungrouped section.
type GroupArrangement struct {
	Group *db.IDPGroup
	IDPs  []ArrangementIDP
}

// ArrangementIDP is a draggable provider entry.
type ArrangementIDP struct {
	ID           string
	FriendlyName string
	ProviderType string
	LogoURL      string
	Enabled      bool
}

// Show renders the provider group arrangement page.
// GET /admin/idp/groups
func (h *AdminIDPGroupHandler) Show(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	groups, err := h.store.ListIDPGroups(r.Context())
	if err != nil {
		h.logger.Error("failed to list provider groups", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to load provider groups")
		return
	}

	idps, err := h.store.ListIDPs(r.Context())
	if err != nil {
		h.logger.Error("failed to list IDPs", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to load identity providers")
		return
	}

	placement, err := h.store.GetLocalAdminPlacement(r.Context())
	if err != nil {
		h.logger.Error("failed to load local admin placement", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to load identity providers")
		return
	}

	// Every group is shown here, including empty ones, so they can be filled.
	// The hide-when-empty rule only applies to the user-facing pages.
	sections := make([]GroupArrangement, 0, len(groups)+1)
	byGroup := make(map[int64][]ArrangementIDP, len(groups))
	known := make(map[int64]bool, len(groups))
	for _, g := range groups {
		known[g.ID] = true
	}

	var ungrouped []ArrangementIDP
	for _, rec := range withLocalAdmin(idps, placement) {
		entry := ArrangementIDP{
			ID:           rec.ID,
			FriendlyName: rec.FriendlyName,
			ProviderType: rec.ProviderType,
			LogoURL:      rec.LogoURL,
			Enabled:      rec.Enabled,
		}
		if rec.GroupID != nil && known[*rec.GroupID] {
			byGroup[*rec.GroupID] = append(byGroup[*rec.GroupID], entry)
			continue
		}
		ungrouped = append(ungrouped, entry)
	}

	for i := range groups {
		sections = append(sections, GroupArrangement{
			Group: &groups[i],
			IDPs:  byGroup[groups[i].ID],
		})
	}

	h.renderer.Render(w, r, "admin_idp_groups.html", PageData{
		Title:   "Provider Groups",
		Session: sess,
		Data: map[string]any{
			"Sections":   sections,
			"Ungrouped":  ungrouped,
			"GroupCount": len(groups),
			"ActivePage": "idp-groups",
		},
	})
}

// Create adds a new provider group.
// POST /admin/idp/groups
func (h *AdminIDPGroupHandler) Create(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" || len([]rune(name)) > maxGroupNameLen {
		h.renderer.RenderError(w, r, http.StatusBadRequest,
			fmt.Sprintf("Group name is required and must be %d characters or fewer", maxGroupNameLen))
		return
	}

	taken, err := h.groupNameTaken(r.Context(), name, 0)
	if err != nil {
		h.logger.Error("failed to list provider groups", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to create provider group")
		return
	}
	if taken {
		h.renderer.RenderError(w, r, http.StatusBadRequest,
			fmt.Sprintf("A provider group named %q already exists", name))
		return
	}

	group := &db.IDPGroup{
		Name:           name,
		Description:    strings.TrimSpace(r.FormValue("description")),
		Icon:           normalizeGroupIcon(r.FormValue("icon")),
		Collapsible:    r.FormValue("collapsible") == "1",
		StartCollapsed: r.FormValue("start_collapsed") == "1",
	}

	if err := h.store.CreateIDPGroup(r.Context(), group); err != nil {
		h.logger.Error("failed to create provider group", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to create provider group")
		return
	}

	h.audit.Log(r.Context(), &db.AuditEntry{
		Username: sess.Username,
		SourceIP: r.RemoteAddr,
		Action:   audit.ActionIDPGroupCreate,
		Result:   "success",
		Details:  fmt.Sprintf("Provider group %q created (id=%d)", group.Name, group.ID),
	})
	h.logger.Info("provider group created", "admin", sess.Username, "group", group.Name, "id", group.ID)

	http.Redirect(w, r, "/admin/idp/groups", http.StatusFound)
}

// Update edits an existing provider group.
// POST /admin/idp/groups/{id}
func (h *AdminIDPGroupHandler) Update(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	id, err := groupIDFromURL(r)
	if err != nil {
		h.renderer.RenderError(w, r, http.StatusBadRequest, "Invalid group ID")
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" || len([]rune(name)) > maxGroupNameLen {
		h.renderer.RenderError(w, r, http.StatusBadRequest,
			fmt.Sprintf("Group name is required and must be %d characters or fewer", maxGroupNameLen))
		return
	}

	taken, err := h.groupNameTaken(r.Context(), name, id)
	if err != nil {
		h.logger.Error("failed to list provider groups", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to update provider group")
		return
	}
	if taken {
		h.renderer.RenderError(w, r, http.StatusBadRequest,
			fmt.Sprintf("A provider group named %q already exists", name))
		return
	}

	group := &db.IDPGroup{
		ID:             id,
		Name:           name,
		Description:    strings.TrimSpace(r.FormValue("description")),
		Icon:           normalizeGroupIcon(r.FormValue("icon")),
		Collapsible:    r.FormValue("collapsible") == "1",
		StartCollapsed: r.FormValue("start_collapsed") == "1",
	}

	if err := h.store.UpdateIDPGroup(r.Context(), group); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			h.renderer.RenderError(w, r, http.StatusNotFound, "Provider group not found")
			return
		}
		h.logger.Error("failed to update provider group", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to update provider group")
		return
	}

	h.audit.Log(r.Context(), &db.AuditEntry{
		Username: sess.Username,
		SourceIP: r.RemoteAddr,
		Action:   audit.ActionIDPGroupUpdate,
		Result:   "success",
		Details:  fmt.Sprintf("Provider group %q updated (id=%d)", group.Name, group.ID),
	})
	h.logger.Info("provider group updated", "admin", sess.Username, "group", group.Name, "id", group.ID)

	http.Redirect(w, r, "/admin/idp/groups", http.StatusFound)
}

// Delete removes a provider group. Its providers become ungrouped.
// POST /admin/idp/groups/{id}/delete
func (h *AdminIDPGroupHandler) Delete(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	id, err := groupIDFromURL(r)
	if err != nil {
		h.renderer.RenderError(w, r, http.StatusBadRequest, "Invalid group ID")
		return
	}

	if err := h.store.DeleteIDPGroup(r.Context(), id); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			h.renderer.RenderError(w, r, http.StatusNotFound, "Provider group not found")
			return
		}
		h.logger.Error("failed to delete provider group", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to delete provider group")
		return
	}

	h.audit.Log(r.Context(), &db.AuditEntry{
		Username: sess.Username,
		SourceIP: r.RemoteAddr,
		Action:   audit.ActionIDPGroupDelete,
		Result:   "success",
		Details:  fmt.Sprintf("Provider group id=%d deleted; its providers are now ungrouped", id),
	})
	h.logger.Info("provider group deleted", "admin", sess.Username, "id", id)

	http.Redirect(w, r, "/admin/idp/groups", http.StatusFound)
}

// arrangeRequest is the JSON body posted by the drag-and-drop UI.
type arrangeRequest struct {
	// GroupOrder lists group IDs in the order they should appear.
	GroupOrder []int64 `json:"group_order"`
	// Sections maps a group ID (or "ungrouped") to the provider IDs it holds,
	// in order.
	Sections []arrangeSection `json:"sections"`
}

type arrangeSection struct {
	GroupID *int64   `json:"group_id"`
	IDPIDs  []string `json:"idp_ids"`
}

// Arrange saves the drag-and-drop layout.
// POST /admin/idp/groups/arrange
func (h *AdminIDPGroupHandler) Arrange(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	var req arrangeRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid arrangement payload")
		return
	}

	groups, err := h.store.ListIDPGroups(r.Context())
	if err != nil {
		h.logger.Error("failed to list provider groups", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "Failed to load provider groups")
		return
	}
	validGroup := make(map[int64]bool, len(groups))
	for _, g := range groups {
		validGroup[g.ID] = true
	}

	idps, err := h.store.ListIDPs(r.Context())
	if err != nil {
		h.logger.Error("failed to list IDPs", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "Failed to load identity providers")
		return
	}
	validIDP := make(map[string]bool, len(idps)+1)
	for _, rec := range idps {
		validIDP[rec.ID] = true
	}
	// Local Admin is arranged like a provider but has no row of its own.
	validIDP[db.LocalAdminIDPID] = true

	// Reject unknown IDs rather than silently dropping them, so a stale page
	// cannot quietly discard part of the layout.
	groupOrder := make([]int64, 0, len(req.GroupOrder))
	for _, id := range req.GroupOrder {
		if !validGroup[id] {
			writeJSONError(w, http.StatusBadRequest, "Unknown provider group in arrangement")
			return
		}
		groupOrder = append(groupOrder, id)
	}

	seen := make(map[string]bool, len(idps))
	placements := make([]db.IDPPlacement, 0, len(idps))
	for _, sec := range req.Sections {
		if sec.GroupID != nil && !validGroup[*sec.GroupID] {
			writeJSONError(w, http.StatusBadRequest, "Unknown provider group in arrangement")
			return
		}
		for i, idpID := range sec.IDPIDs {
			if !validIDP[idpID] {
				writeJSONError(w, http.StatusBadRequest, "Unknown identity provider in arrangement")
				return
			}
			if seen[idpID] {
				writeJSONError(w, http.StatusBadRequest, "Identity provider listed more than once")
				return
			}
			seen[idpID] = true
			placements = append(placements, db.IDPPlacement{
				IDPID:        idpID,
				GroupID:      sec.GroupID,
				DisplayOrder: i,
			})
		}
	}

	if err := h.store.SetIDPArrangement(r.Context(), groupOrder, placements); err != nil {
		h.logger.Error("failed to save arrangement", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "Failed to save arrangement")
		return
	}

	h.audit.Log(r.Context(), &db.AuditEntry{
		Username: sess.Username,
		SourceIP: r.RemoteAddr,
		Action:   audit.ActionIDPGroupsArrange,
		Result:   "success",
		Details:  fmt.Sprintf("Arranged %d provider(s) across %d group(s)", len(placements), len(groupOrder)),
	})
	h.logger.Info("provider arrangement saved", "admin", sess.Username,
		"providers", len(placements), "groups", len(groupOrder))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
}

// groupIDFromURL parses the {id} path parameter.
func groupIDFromURL(r *http.Request) (int64, error) {
	return strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
}

// groupNameTaken reports whether a group other than excludeID already uses this
// name. Import matches groups by name, so duplicates would be ambiguous when the
// configuration is moved to another installation.
func (h *AdminIDPGroupHandler) groupNameTaken(ctx context.Context, name string, excludeID int64) (bool, error) {
	groups, err := h.store.ListIDPGroups(ctx)
	if err != nil {
		return false, err
	}
	for _, g := range groups {
		if g.ID != excludeID && strings.EqualFold(g.Name, name) {
			return true, nil
		}
	}
	return false, nil
}

// normalizeGroupIcon keeps only a Bootstrap Icons class name, since the value is
// interpolated straight into a class attribute.
func normalizeGroupIcon(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "bi-") {
		return ""
	}
	for _, r := range v {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			continue
		}
		return ""
	}
	return v
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
