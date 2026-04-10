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

// reportTypeMeta describes a report type for use in the admin UI.
type reportTypeMeta struct {
	Title        string
	Description  string
	TemplateType string
}

// reportTypes defines the two supported report types.
var reportTypes = map[string]reportTypeMeta{
	db.ReportTypeExpiration: {
		Title:        "Soon-to-Expire Passwords",
		Description:  "Accounts whose passwords are expiring soon.",
		TemplateType: "expiration_report",
	},
	db.ReportTypeExpired: {
		Title:        "Expired Accounts",
		Description:  "Accounts whose passwords have already expired.",
		TemplateType: "expired_accounts_report",
	},
}

// idpReportEntry pairs an IDP record with per-type report configs for the list view.
type idpReportEntry struct {
	IDP        db.IdentityProviderRecord
	Expiration *db.ReportConfig
	Expired    *db.ReportConfig
}

// AdminReportsHandler handles report configuration in the admin UI.
type AdminReportsHandler struct {
	store    db.Store
	reporter *job.ReportScheduler
	renderer *Renderer
	audit    *audit.Logger
	logger   *slog.Logger
}

// NewAdminReportsHandler creates a new AdminReportsHandler.
func NewAdminReportsHandler(
	store db.Store,
	reporter *job.ReportScheduler,
	renderer *Renderer,
	auditLogger *audit.Logger,
	logger *slog.Logger,
) *AdminReportsHandler {
	return &AdminReportsHandler{
		store:    store,
		reporter: reporter,
		renderer: renderer,
		audit:    auditLogger,
		logger:   logger,
	}
}

// List renders the reports overview page showing all IDPs with their report status.
// GET /admin/reports
func (h *AdminReportsHandler) List(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())

	idps, err := h.store.ListIDPs(r.Context())
	if err != nil {
		h.logger.Error("failed to list IDPs", "error", err)
		h.renderer.RenderError(w, r, http.StatusInternalServerError, "Failed to load identity providers")
		return
	}

	var items []idpReportEntry
	for _, idpRec := range idps {
		configs, _ := h.store.ListReportConfigsForIDP(r.Context(), idpRec.ID)
		entry := idpReportEntry{IDP: idpRec}
		for i := range configs {
			c := &configs[i]
			switch c.ReportType {
			case db.ReportTypeExpiration:
				entry.Expiration = c
			case db.ReportTypeExpired:
				entry.Expired = c
			}
		}
		items = append(items, entry)
	}

	h.renderer.Render(w, r, "admin_reports.html", PageData{
		Title:   "Reports",
		Session: sess,
		Data: map[string]any{
			"Items":      items,
			"ActivePage": "reports",
		},
	})
}

// Show renders the report configuration page for a specific IDP and report type.
// GET /admin/reports/{id}/{type}
func (h *AdminReportsHandler) Show(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	idpID := chi.URLParam(r, "id")
	reportType := chi.URLParam(r, "type")

	meta, ok := reportTypes[reportType]
	if !ok {
		h.renderer.RenderError(w, r, http.StatusNotFound, "Unknown report type")
		return
	}

	record, err := h.store.GetIDP(r.Context(), idpID)
	if err != nil {
		h.logger.Error("failed to load IDP", "error", err, "idp_id", idpID)
		h.renderer.RenderError(w, r, http.StatusNotFound, "Identity provider not found")
		return
	}

	cfg, _ := h.store.GetReportConfig(r.Context(), idpID, reportType)
	if cfg == nil {
		cfg = &db.ReportConfig{
			IDPID:                idpID,
			ReportType:           reportType,
			Enabled:              false,
			CronSchedule:         "0 7 * * 1",
			DaysBeforeExpiration: 14,
			ExcludeDisabled:      true,
		}
	}

	filters, err := h.store.ListReportFilters(r.Context(), idpID, reportType)
	if err != nil {
		h.logger.Error("failed to load report filters", "error", err, "idp_id", idpID)
		filters = nil
	}

	// For FreeIPA with no saved filters yet, pre-populate the nsAccountLock default.
	if len(filters) == 0 && record.ProviderType == "freeipa" {
		filters = []db.ReportFilter{
			{
				IDPID:       idpID,
				ReportType:  reportType,
				Attribute:   "nsAccountLock",
				Pattern:     "(?i)^true$",
				Description: "Exclude disabled accounts",
			},
		}
	}

	h.renderer.Render(w, r, "admin_report_config.html", PageData{
		Title:   meta.Title + " – " + record.FriendlyName,
		Session: sess,
		Data: map[string]any{
			"IDP":        record,
			"Config":     cfg,
			"Filters":    filters,
			"Meta":       meta,
			"ReportType": reportType,
			"ActivePage": "reports",
		},
	})
}

// Save processes the report configuration form.
// POST /admin/reports/{id}/{type}
func (h *AdminReportsHandler) Save(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	idpID := chi.URLParam(r, "id")
	reportType := chi.URLParam(r, "type")

	meta, ok := reportTypes[reportType]
	if !ok {
		h.renderer.RenderError(w, r, http.StatusNotFound, "Unknown report type")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.renderer.RenderError(w, r, http.StatusBadRequest, "Invalid form data")
		return
	}

	record, err := h.store.GetIDP(r.Context(), idpID)
	if err != nil {
		h.renderer.RenderError(w, r, http.StatusNotFound, "Identity provider not found")
		return
	}

	enabled := r.FormValue("enabled") == "on"
	cronSchedule := r.FormValue("cron_schedule")
	daysStr := r.FormValue("days_before_expiration")
	recipients := r.FormValue("recipients")
	excludeDisabled := r.FormValue("exclude_disabled") == "on"

	days, err := strconv.Atoi(daysStr)
	if err != nil || days < 1 || days > 90 {
		days = 14
	}

	if cronSchedule == "" {
		cronSchedule = "0 7 * * 1"
	}
	if _, err := cron.ParseStandard(cronSchedule); err != nil {
		h.renderer.Render(w, r, "admin_report_config.html", PageData{
			Title:   meta.Title + " – " + record.FriendlyName,
			Session: sess,
			Flash:   map[string]string{"category": "error", "message": "Invalid cron schedule: " + err.Error()},
			Data: map[string]any{
				"IDP":  record,
				"Meta": meta,
				"Config": &db.ReportConfig{
					IDPID:                idpID,
					ReportType:           reportType,
					Enabled:              enabled,
					CronSchedule:         cronSchedule,
					DaysBeforeExpiration: days,
					Recipients:           recipients,
					ExcludeDisabled:      excludeDisabled,
				},
				"Filters":    buildReportFiltersFromForm(r, idpID, reportType),
				"ReportType": reportType,
				"ActivePage": "reports",
			},
		})
		return
	}

	cfg := &db.ReportConfig{
		IDPID:                idpID,
		ReportType:           reportType,
		Enabled:              enabled,
		CronSchedule:         cronSchedule,
		DaysBeforeExpiration: days,
		Recipients:           recipients,
		ExcludeDisabled:      excludeDisabled,
		UpdatedAt:            time.Now().UTC(),
	}

	if err := h.store.SaveReportConfig(r.Context(), cfg); err != nil {
		h.logger.Error("failed to save report config", "error", err, "idp_id", idpID)
		h.renderer.Render(w, r, "admin_report_config.html", PageData{
			Title:   meta.Title + " – " + record.FriendlyName,
			Session: sess,
			Flash:   map[string]string{"category": "error", "message": "Failed to save configuration"},
			Data: map[string]any{
				"IDP":        record,
				"Config":     cfg,
				"Meta":       meta,
				"Filters":    buildReportFiltersFromForm(r, idpID, reportType),
				"ReportType": reportType,
				"ActivePage": "reports",
			},
		})
		return
	}

	filters := buildReportFiltersFromForm(r, idpID, reportType)

	if err := h.store.SaveReportFilters(r.Context(), idpID, reportType, filters); err != nil {
		h.logger.Error("failed to save report filters", "error", err, "idp_id", idpID)
		h.renderer.Render(w, r, "admin_report_config.html", PageData{
			Title:   meta.Title + " – " + record.FriendlyName,
			Session: sess,
			Flash:   map[string]string{"category": "error", "message": "Failed to save filters"},
			Data: map[string]any{
				"IDP":        record,
				"Config":     cfg,
				"Meta":       meta,
				"Filters":    filters,
				"ReportType": reportType,
				"ActivePage": "reports",
			},
		})
		return
	}

	h.reporter.ReloadSchedules(r.Context())

	h.audit.Log(r.Context(), &db.AuditEntry{
		Timestamp:  time.Now().UTC(),
		Username:   sess.Username,
		SourceIP:   r.RemoteAddr,
		Action:     audit.ActionReportConfigUpdate,
		ProviderID: idpID,
		Result:     audit.ResultSuccess,
		Details:    fmt.Sprintf("Updated %s report config (enabled=%v, schedule=%s, days=%d, recipients=%s, excludeDisabled=%v, filters=%d)", reportType, enabled, cronSchedule, days, recipients, excludeDisabled, len(filters)),
	})

	savedFilters, err := h.store.ListReportFilters(r.Context(), idpID, reportType)
	if err != nil {
		savedFilters = filters
	}

	h.renderer.Render(w, r, "admin_report_config.html", PageData{
		Title:   meta.Title + " – " + record.FriendlyName,
		Session: sess,
		Flash:   map[string]string{"category": "success", "message": "Report settings saved successfully"},
		Data: map[string]any{
			"IDP":        record,
			"Config":     cfg,
			"Meta":       meta,
			"Filters":    savedFilters,
			"ReportType": reportType,
			"ActivePage": "reports",
		},
	})
}

// SendNow triggers an immediate report generation and sends it via email.
// POST /admin/reports/{id}/{type}/send
func (h *AdminReportsHandler) SendNow(w http.ResponseWriter, r *http.Request) {
	idpID := chi.URLParam(r, "id")
	reportType := chi.URLParam(r, "type")

	if _, ok := reportTypes[reportType]; !ok {
		h.renderer.JSON(w, http.StatusBadRequest, map[string]any{
			"status":  "error",
			"message": "Unknown report type",
		})
		return
	}

	if err := h.reporter.RunReportForIDP(r.Context(), idpID, reportType); err != nil {
		h.renderer.JSON(w, http.StatusOK, map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	h.renderer.JSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"message": "Report generated and sent successfully",
	})
}

// Preview generates a report preview without sending email.
// POST /admin/reports/{id}/{type}/preview
func (h *AdminReportsHandler) Preview(w http.ResponseWriter, r *http.Request) {
	idpID := chi.URLParam(r, "id")
	reportType := chi.URLParam(r, "type")

	if _, ok := reportTypes[reportType]; !ok {
		h.renderer.JSON(w, http.StatusBadRequest, map[string]any{
			"status":  "error",
			"message": "Unknown report type",
		})
		return
	}

	result, err := h.reporter.PreviewForIDP(r.Context(), idpID, reportType)
	if err != nil {
		h.renderer.JSON(w, http.StatusOK, map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	h.renderer.JSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"html":   result.HTML,
		"count":  result.Count,
	})
}

// buildReportFiltersFromForm parses the dynamic filter rows from the form.
func buildReportFiltersFromForm(r *http.Request, idpID, reportType string) []db.ReportFilter {
	attributes := r.Form["filter_attribute[]"]
	patterns := r.Form["filter_pattern[]"]
	descriptions := r.Form["filter_description[]"]

	var filters []db.ReportFilter
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
		filters = append(filters, db.ReportFilter{
			IDPID:       idpID,
			ReportType:  reportType,
			Attribute:   attr,
			Pattern:     pattern,
			Description: desc,
		})
	}
	return filters
}
