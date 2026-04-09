// Package handler provides HTTP handlers for the PassPort application.
package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/hanej/passport/internal/db"
)

// HealthHandler serves liveness and readiness probes.
type HealthHandler struct {
	db     *db.DB
	logger *slog.Logger
}

// NewHealthHandler creates a HealthHandler backed by the given database.
func NewHealthHandler(database *db.DB, logger *slog.Logger) *HealthHandler {
	return &HealthHandler{
		db:     database,
		logger: logger,
	}
}

// Liveness always returns 200 OK. It indicates the process is running.
func (h *HealthHandler) Liveness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// Readiness verifies the database is reachable and all migrations have been
// applied. It returns 200 when ready, or 503 with an error description.
func (h *HealthHandler) Readiness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	ctx := r.Context()

	if err := h.db.Ping(ctx); err != nil {
		h.logger.Warn("readiness check failed: database ping", "error", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "not ready",
			"error":  err.Error(),
		})
		return
	}

	complete, err := h.db.MigrationsComplete(ctx)
	if err != nil {
		h.logger.Warn("readiness check failed: migrations check", "error", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "not ready",
			"error":  err.Error(),
		})
		return
	}
	if !complete {
		h.logger.Warn("readiness check failed: migrations not complete")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "not ready",
			"error":  "migrations not complete",
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
}
