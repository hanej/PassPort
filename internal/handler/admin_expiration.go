package handler

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/robfig/cron/v3"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/job"
)

// AdminExpirationHandler handles password expiration notification configuration.
type AdminExpirationHandler struct {
	store    db.Store
	notifier *job.PasswordExpirationNotifier
	renderer *Renderer
	audit    *audit.Logger
	logger   *slog.Logger
}

// NewAdminExpirationHandler creates a new AdminExpirationHandler.
func NewAdminExpirationHandler(
	store db.Store,
	notifier *job.PasswordExpirationNotifier,
	renderer *Renderer,
	auditLogger *audit.Logger,
	logger *slog.Logger,
) *AdminExpirationHandler {
	return &AdminExpirationHandler{
		store:    store,
		notifier: notifier,
		renderer: renderer,
		audit:    auditLogger,
		logger:   logger,
	}
}

// Show renders the password expiration configuration page.
// GET /admin/idp/{id}/expiration
func (h *AdminExpirationHandler) Show(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Show expiration config called")

	sess := auth.SessionFromContext(r.Context())
	idpID := chi.URLParam(r, "id")

	h.logger.Debug("loading expiration config", "idp_id", idpID)

	// Load IDP record for breadcrumb name.
	record, err := h.store.GetIDP(r.Context(), idpID)
	if err != nil {
		h.logger.Error("failed to load IDP", "error", err, "idp_id", idpID)
		h.renderer.RenderError(w, r, http.StatusNotFound, "Identity provider not found")
		return
	}

	// Load expiration config (nil is ok, means new).
	cfg, err := h.store.GetExpirationConfig(r.Context(), idpID)
	if err != nil {
		h.logger.Debug("no expiration config found, using defaults", "error", err, "idp_id", idpID)
	}

	// Apply defaults if nil.
	if cfg == nil {
		cfg = &db.ExpirationConfig{
			IDPID:                idpID,
			Enabled:              false,
			CronSchedule:         "0 6 * * *",
			DaysBeforeExpiration: 14,
		}
	}

	// Load filters.
	filters, err := h.store.ListExpirationFilters(r.Context(), idpID)
	if err != nil {
		h.logger.Error("failed to load expiration filters", "error", err, "idp_id", idpID)
		filters = nil
	}

	h.logger.Debug("expiration config loaded",
		"idp_id", idpID,
		"enabled", cfg.Enabled,
		"schedule", cfg.CronSchedule,
		"days_before", cfg.DaysBeforeExpiration,
		"filter_count", len(filters),
	)

	h.renderer.Render(w, r, "admin_idp_expiration.html", PageData{
		Title:   "Password Expiration - " + record.FriendlyName,
		Session: sess,
		Data: map[string]any{
			"IDP":        record,
			"Config":     cfg,
			"Filters":    filters,
			"ActivePage": "idp",
		},
	})
}

// Save processes the expiration configuration form.
// POST /admin/idp/{id}/expiration
func (h *AdminExpirationHandler) Save(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Save expiration config called")

	sess := auth.SessionFromContext(r.Context())
	idpID := chi.URLParam(r, "id")

	h.logger.Debug("saving expiration config", "idp_id", idpID)

	if err := r.ParseForm(); err != nil {
		h.renderer.RenderError(w, r, http.StatusBadRequest, "Invalid form data")
		return
	}

	// Load IDP record for breadcrumb name.
	record, err := h.store.GetIDP(r.Context(), idpID)
	if err != nil {
		h.logger.Error("failed to load IDP", "error", err, "idp_id", idpID)
		h.renderer.RenderError(w, r, http.StatusNotFound, "Identity provider not found")
		return
	}

	enabled := r.FormValue("enabled") == "on"
	cronSchedule := r.FormValue("cron_schedule")
	daysStr := r.FormValue("days_before_expiration")

	days, err := strconv.Atoi(daysStr)
	if err != nil || days < 1 || days > 90 {
		days = 14
	}

	// Validate cron schedule.
	if cronSchedule == "" {
		cronSchedule = "0 6 * * *"
	}
	if _, err := cron.ParseStandard(cronSchedule); err != nil {
		h.logger.Debug("invalid cron schedule", "schedule", cronSchedule, "error", err)
		h.renderer.Render(w, r, "admin_idp_expiration.html", PageData{
			Title:   "Password Expiration - " + record.FriendlyName,
			Session: sess,
			Flash:   map[string]string{"category": "error", "message": "Invalid cron schedule: " + err.Error()},
			Data: map[string]any{
				"IDP": record,
				"Config": &db.ExpirationConfig{
					IDPID:                idpID,
					Enabled:              enabled,
					CronSchedule:         cronSchedule,
					DaysBeforeExpiration: days,
				},
				"Filters":    buildFiltersFromForm(r, idpID),
				"ActivePage": "idp",
			},
		})
		return
	}

	// Save config.
	cfg := &db.ExpirationConfig{
		IDPID:                idpID,
		Enabled:              enabled,
		CronSchedule:         cronSchedule,
		DaysBeforeExpiration: days,
		UpdatedAt:            time.Now().UTC(),
	}

	if err := h.store.SaveExpirationConfig(r.Context(), cfg); err != nil {
		h.logger.Error("failed to save expiration config", "error", err, "idp_id", idpID)
		h.renderer.Render(w, r, "admin_idp_expiration.html", PageData{
			Title:   "Password Expiration - " + record.FriendlyName,
			Session: sess,
			Flash:   map[string]string{"category": "error", "message": "Failed to save configuration"},
			Data: map[string]any{
				"IDP":        record,
				"Config":     cfg,
				"Filters":    buildFiltersFromForm(r, idpID),
				"ActivePage": "idp",
			},
		})
		return
	}

	// Parse and save filters.
	filters := buildFiltersFromForm(r, idpID)

	if err := h.store.SaveExpirationFilters(r.Context(), idpID, filters); err != nil {
		h.logger.Error("failed to save expiration filters", "error", err, "idp_id", idpID)
		h.renderer.Render(w, r, "admin_idp_expiration.html", PageData{
			Title:   "Password Expiration - " + record.FriendlyName,
			Session: sess,
			Flash:   map[string]string{"category": "error", "message": "Failed to save filters"},
			Data: map[string]any{
				"IDP":        record,
				"Config":     cfg,
				"Filters":    filters,
				"ActivePage": "idp",
			},
		})
		return
	}

	// Reload cron schedules.
	h.notifier.ReloadSchedules(r.Context())

	h.logger.Debug("expiration config saved successfully",
		"idp_id", idpID,
		"enabled", enabled,
		"schedule", cronSchedule,
		"days_before", days,
		"filter_count", len(filters),
	)

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp:  time.Now().UTC(),
		Username:   sess.Username,
		SourceIP:   r.RemoteAddr,
		Action:     audit.ActionExpirationConfigUpdate,
		ProviderID: idpID,
		Result:     audit.ResultSuccess,
		Details:    fmt.Sprintf("Updated expiration config (enabled=%v, schedule=%s, days=%d, filters=%d)", enabled, cronSchedule, days, len(filters)),
	})

	// Reload filters from DB for display.
	savedFilters, err := h.store.ListExpirationFilters(r.Context(), idpID)
	if err != nil {
		h.logger.Error("failed to reload filters after save", "error", err)
		savedFilters = filters
	}

	h.renderer.Render(w, r, "admin_idp_expiration.html", PageData{
		Title:   "Password Expiration - " + record.FriendlyName,
		Session: sess,
		Flash:   map[string]string{"category": "success", "message": "Password expiration settings saved successfully"},
		Data: map[string]any{
			"IDP":        record,
			"Config":     cfg,
			"Filters":    savedFilters,
			"ActivePage": "idp",
		},
	})
}

// RunNow triggers an immediate expiration scan for a single IDP. Returns JSON.
// POST /admin/idp/{id}/expiration/run
func (h *AdminExpirationHandler) RunNow(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("RunNow called")

	idpID := chi.URLParam(r, "id")

	h.logger.Debug("running expiration scan now", "idp_id", idpID)

	count, err := h.notifier.RunForIDP(r.Context(), idpID)
	if err != nil {
		h.logger.Error("run now failed", "error", err, "idp_id", idpID)
		h.renderer.JSON(w, http.StatusOK, map[string]any{
			"status":  "error",
			"message": err.Error(),
			"count":   0,
		})
		return
	}

	h.logger.Debug("run now completed", "idp_id", idpID, "count", count)

	h.renderer.JSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"message": fmt.Sprintf("Scan complete: %d notification(s) sent", count),
		"count":   count,
	})
}

// DryRun executes a test scan without sending emails. Returns JSON with per-user results.
// POST /admin/idp/{id}/expiration/dry-run
func (h *AdminExpirationHandler) DryRun(w http.ResponseWriter, r *http.Request) {
	idpID := chi.URLParam(r, "id")
	h.logger.Debug("DryRun called", "idp_id", idpID)

	result, err := h.notifier.DryRunForIDP(r.Context(), idpID)
	if err != nil {
		h.logger.Error("dry run failed", "error", err, "idp_id", idpID)
		h.renderer.JSON(w, http.StatusOK, map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	h.renderer.JSON(w, http.StatusOK, map[string]any{
		"status":         "success",
		"total_users":    result.TotalUsers,
		"excluded_count": result.ExcludedCount,
		"eligible_count": result.EligibleCount,
		"users":          result.Users,
	})
}

// buildFiltersFromForm parses the dynamic filter rows from the form.
func buildFiltersFromForm(r *http.Request, idpID string) []db.ExpirationFilter {
	attributes := r.Form["filter_attribute[]"]
	patterns := r.Form["filter_pattern[]"]
	descriptions := r.Form["filter_description[]"]

	var filters []db.ExpirationFilter
	for i := range attributes {
		attr := attributes[i]
		if attr == "" {
			continue
		}
		pattern := ""
		if i < len(patterns) {
			pattern = patterns[i]
		}
		if pattern == "" {
			continue
		}
		desc := ""
		if i < len(descriptions) {
			desc = descriptions[i]
		}
		filters = append(filters, db.ExpirationFilter{
			IDPID:       idpID,
			Attribute:   attr,
			Pattern:     pattern,
			Description: desc,
		})
	}
	return filters
}
