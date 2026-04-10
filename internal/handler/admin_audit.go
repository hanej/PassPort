package handler

import (
	"log/slog"
	"math"
	"net/http"
	"strconv"

	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/db"
)

const auditPageSize = 50

// AdminAuditHandler handles the audit log viewer in the admin UI.
type AdminAuditHandler struct {
	store    db.Store
	renderer *Renderer
	logger   *slog.Logger
}

// NewAdminAuditHandler creates a new AdminAuditHandler.
func NewAdminAuditHandler(
	store db.Store,
	renderer *Renderer,
	logger *slog.Logger,
) *AdminAuditHandler {
	return &AdminAuditHandler{
		store:    store,
		renderer: renderer,
		logger:   logger,
	}
}

// List renders the audit log page with filters and pagination.
// GET /admin/audit
func (h *AdminAuditHandler) List(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	h.logger.Debug("List audit entries called",
		"username_filter", r.URL.Query().Get("username"),
		"action_filter", r.URL.Query().Get("action"),
		"result_filter", r.URL.Query().Get("result"),
	)

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	filter := db.AuditFilter{
		Username:  r.URL.Query().Get("username"),
		Action:    r.URL.Query().Get("action"),
		Result:    r.URL.Query().Get("result"),
		StartDate: r.URL.Query().Get("start_date"),
		EndDate:   r.URL.Query().Get("end_date"),
		Limit:     auditPageSize,
		Offset:    (page - 1) * auditPageSize,
	}

	entries, totalCount, err := h.store.ListAudit(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to list audit entries", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to load audit log")
		return
	}

	h.logger.Debug("audit entries loaded",
		"result_count", len(entries),
		"total_count", totalCount,
	)

	totalPages := int(math.Ceil(float64(totalCount) / float64(auditPageSize)))
	if totalPages < 1 {
		totalPages = 1
	}

	// Build base URL for pagination links, preserving filter params.
	baseURL := "/admin/audit?"
	q := r.URL.Query()
	q.Del("page")
	baseURL += q.Encode()

	h.renderer.Render(w, r, "admin_audit.html", PageData{
		Title:   "Audit Log",
		Session: sess,
		Data: map[string]any{
			"Entries":     entries,
			"CurrentPage": page,
			"TotalPages":  totalPages,
			"TotalCount":  totalCount,
			"BaseURL":     baseURL,
			"Filter":      filter,
			"ActivePage":  "audit",
		},
	})
}
