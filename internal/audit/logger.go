package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/logging"
)

// Logger writes audit events to both the database and an append-only JSON file.
type Logger struct {
	store db.AuditStore
	file  *logging.RotatableFile
	mu    sync.Mutex // protects file writes
	slog  *slog.Logger
}

// fileEntry is the JSON structure written to the audit log file.
type fileEntry struct {
	Timestamp    string `json:"timestamp"`
	Username     string `json:"username"`
	SourceIP     string `json:"source_ip"`
	Action       string `json:"action"`
	ProviderID   string `json:"provider_id,omitempty"`
	ProviderName string `json:"provider_name,omitempty"`
	Result       string `json:"result"`
	Details      string `json:"details,omitempty"`
}

// NewLogger creates a Logger that writes to the given store and file path.
// The file is opened in append-only mode and created if it doesn't exist.
// The file supports rotation via Reopen() when SIGHUP is received.
func NewLogger(store db.AuditStore, filePath string, slogger *slog.Logger) (*Logger, error) {
	f, err := logging.NewRotatableFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening audit log file %s: %w", filePath, err)
	}

	return &Logger{
		store: store,
		file:  f,
		slog:  slogger,
	}, nil
}

// ReopenFile closes and reopens the audit log file for log rotation.
func (l *Logger) ReopenFile() error {
	return l.file.Reopen()
}

// Log records an audit event to both the database and the file.
// File write errors are logged but do not cause the method to fail,
// since the database is the primary queryable store.
func (l *Logger) Log(ctx context.Context, entry *db.AuditEntry) {
	// Resolve ProviderName from the IDP registry when the caller did not set it.
	if entry.ProviderID != "" && entry.ProviderName == "" {
		if rec, err := l.store.GetIDP(ctx, entry.ProviderID); err != nil {
			l.slog.Warn("audit: could not resolve provider name",
				"provider_id", entry.ProviderID,
				"error", err,
			)
		} else if rec != nil {
			entry.ProviderName = rec.FriendlyName
		}
	}

	// Write to database
	if err := l.store.AppendAudit(ctx, entry); err != nil {
		l.slog.Error("failed to write audit entry to database",
			"error", err,
			"action", entry.Action,
			"username", entry.Username,
		)
	}

	// Write to file (best-effort, never blocks callers on failure)
	l.writeToFile(entry)
}

func (l *Logger) writeToFile(entry *db.AuditEntry) {
	ts := entry.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	fe := fileEntry{
		Timestamp:    ts.Format(time.RFC3339Nano),
		Username:     entry.Username,
		SourceIP:     entry.SourceIP,
		Action:       entry.Action,
		ProviderID:   entry.ProviderID,
		ProviderName: entry.ProviderName,
		Result:       entry.Result,
		Details:      entry.Details,
	}

	data, err := json.Marshal(fe)
	if err != nil {
		l.slog.Error("failed to marshal audit entry for file", "error", err)
		return
	}
	data = append(data, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	if _, err := l.file.Write(data); err != nil {
		l.slog.Error("failed to write audit entry to file", "error", err)
	}
}

// Close closes the audit log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

// StartDBPurge starts a background goroutine that periodically deletes audit entries
// older than the given retention duration from the database.
// It stops when the context is cancelled.
func (l *Logger) StartDBPurge(ctx context.Context, retention time.Duration, interval time.Duration) {
	if retention <= 0 {
		l.slog.Info("audit DB purge disabled (retention=0)")
		return
	}
	l.slog.Info("audit DB purge started", "retention", retention, "interval", interval)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				l.slog.Info("audit DB purge stopped")
				return
			case <-ticker.C:
				cutoff := time.Now().UTC().Add(-retention)
				count, err := l.store.PurgeAuditBefore(ctx, cutoff)
				if err != nil {
					l.slog.Error("audit DB purge failed", "error", err)
				} else if count > 0 {
					l.slog.Info("audit DB purge completed", "deleted", count, "cutoff", cutoff)
				}
			}
		}
	}()
}
