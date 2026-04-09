package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/hanej/passport/internal/db"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func setupTestDB(t *testing.T) *db.DB {
	t.Helper()
	database, err := db.OpenMemory()
	if err != nil {
		t.Fatalf("opening memory db: %v", err)
	}
	if err := database.Migrate(context.Background()); err != nil {
		t.Fatalf("running migrations: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func TestLiveness(t *testing.T) {
	database := setupTestDB(t)
	h := NewHealthHandler(database, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	h.Liveness(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %s", ct)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("expected status ok, got %s", body["status"])
	}
}

func TestReadiness_Healthy(t *testing.T) {
	database := setupTestDB(t)
	h := NewHealthHandler(database, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	h.Readiness(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %s", ct)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body["status"] != "ready" {
		t.Fatalf("expected status ready, got %s", body["status"])
	}
}

func TestReadiness_DBUnreachable(t *testing.T) {
	database := setupTestDB(t)
	h := NewHealthHandler(database, testLogger())

	// Close the database to simulate an unreachable DB.
	_ = database.Close()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	h.Readiness(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", rec.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body["status"] != "not ready" {
		t.Fatalf("expected status 'not ready', got %s", body["status"])
	}
	if body["error"] == "" {
		t.Fatal("expected error field to be non-empty")
	}
}

// TestReadiness_MigrationsCheckError covers the path where MigrationsComplete
// returns an error (schema_migrations table missing).
func TestReadiness_MigrationsCheckError(t *testing.T) {
	// Open a DB without running migrations so schema_migrations doesn't exist.
	database, err := db.OpenMemory()
	if err != nil {
		t.Fatalf("opening memory db: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	h := NewHealthHandler(database, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.Readiness(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for missing schema_migrations, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body["status"] != "not ready" {
		t.Errorf("expected 'not ready', got %s", body["status"])
	}
}

// TestReadiness_MigrationsNotComplete covers the path where MigrationsComplete
// returns false (some migrations are missing).
func TestReadiness_MigrationsNotComplete(t *testing.T) {
	database := setupTestDB(t)

	// Delete a migration record to simulate incomplete migrations.
	if _, err := database.Writer().ExecContext(context.Background(), "DELETE FROM schema_migrations WHERE version = 1"); err != nil {
		t.Fatalf("deleting migration: %v", err)
	}

	h := NewHealthHandler(database, testLogger())
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.Readiness(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for incomplete migrations, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body["status"] != "not ready" {
		t.Errorf("expected 'not ready', got %s", body["status"])
	}
}
