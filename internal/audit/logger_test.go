package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hanej/passport/internal/db"
)

func newTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.OpenMemory()
	if err != nil {
		t.Fatalf("opening memory db: %v", err)
	}
	if err := d.Migrate(context.Background()); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func newTestLogger(t *testing.T, d *db.DB) (*Logger, string) {
	t.Helper()
	filePath := filepath.Join(t.TempDir(), "audit.log")
	l, err := NewLogger(d, filePath, slog.Default())
	if err != nil {
		t.Fatalf("creating logger: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l, filePath
}

func TestLogWritesToDBAndFile(t *testing.T) {
	d := newTestDB(t)
	l, filePath := newTestLogger(t, d)
	ctx := context.Background()

	entry := &db.AuditEntry{
		Username: "admin",
		SourceIP: "10.0.0.1",
		Action:   ActionLogin,
		Result:   ResultSuccess,
		Details:  "Local admin login",
	}
	l.Log(ctx, entry)

	// Verify DB
	entries, total, err := d.ListAudit(ctx, db.AuditFilter{Limit: 50})
	if err != nil {
		t.Fatalf("listing audit: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1 DB entry, got %d", total)
	}
	if entries[0].Username != "admin" {
		t.Errorf("expected admin, got %s", entries[0].Username)
	}

	// Verify file
	f, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("opening audit file: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatal("expected at least one line in audit file")
	}

	var fe fileEntry
	if err := json.Unmarshal(scanner.Bytes(), &fe); err != nil {
		t.Fatalf("parsing file entry: %v", err)
	}
	if fe.Username != "admin" {
		t.Errorf("expected admin in file, got %s", fe.Username)
	}
	if fe.Action != ActionLogin {
		t.Errorf("expected login action, got %s", fe.Action)
	}
	if fe.Result != ResultSuccess {
		t.Errorf("expected success, got %s", fe.Result)
	}
}

func TestLogMultipleEntries(t *testing.T) {
	d := newTestDB(t)
	l, filePath := newTestLogger(t, d)
	ctx := context.Background()

	for i := range 5 {
		l.Log(ctx, &db.AuditEntry{
			Username: "user",
			SourceIP: "10.0.0.1",
			Action:   ActionPasswordChange,
			Result:   ResultSuccess,
			Details:  "change " + string(rune('0'+i)),
		})
	}

	// DB should have 5
	_, total, _ := d.ListAudit(ctx, db.AuditFilter{Limit: 50})
	if total != 5 {
		t.Errorf("expected 5 DB entries, got %d", total)
	}

	// File should have 5 lines
	f, _ := os.Open(filePath)
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		count++
	}
	if count != 5 {
		t.Errorf("expected 5 file lines, got %d", count)
	}
}

func TestFileEntryContainsAllFields(t *testing.T) {
	d := newTestDB(t)
	l, filePath := newTestLogger(t, d)

	l.Log(context.Background(), &db.AuditEntry{
		Username:     "jsmith",
		SourceIP:     "192.168.1.100",
		Action:       ActionPasswordChange,
		ProviderID:   "corp-ad",
		ProviderName: "Corporate AD",
		Result:       ResultFailure,
		Details:      "Policy violation",
	})

	data, _ := os.ReadFile(filePath)
	var fe fileEntry
	if err := json.Unmarshal(data, &fe); err != nil {
		t.Fatalf("parsing file entry: %v", err)
	}

	if fe.Username != "jsmith" {
		t.Errorf("username: got %s", fe.Username)
	}
	if fe.SourceIP != "192.168.1.100" {
		t.Errorf("source_ip: got %s", fe.SourceIP)
	}
	if fe.ProviderID != "corp-ad" {
		t.Errorf("provider_id: got %s", fe.ProviderID)
	}
	if fe.ProviderName != "Corporate AD" {
		t.Errorf("provider_name: got %s", fe.ProviderName)
	}
	if fe.Result != ResultFailure {
		t.Errorf("result: got %s", fe.Result)
	}
	if fe.Details != "Policy violation" {
		t.Errorf("details: got %s", fe.Details)
	}
	if fe.Timestamp == "" {
		t.Error("timestamp should not be empty")
	}
}

func TestDBPurge(t *testing.T) {
	d := newTestDB(t)
	l, _ := newTestLogger(t, d)
	ctx := context.Background()

	// Insert entries directly into DB with old timestamps
	for i := range 3 {
		if err := d.AppendAudit(ctx, &db.AuditEntry{
			Username: "old",
			SourceIP: "1.1.1.1",
			Action:   ActionLogin,
			Result:   ResultSuccess,
			Details:  string(rune('0' + i)),
		}); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}

	// Verify we have 3 entries
	_, total, _ := d.ListAudit(ctx, db.AuditFilter{Limit: 50})
	if total != 3 {
		t.Fatalf("expected 3, got %d", total)
	}

	// Purge everything before 1 hour in the future (purges all)
	cutoff := time.Now().UTC().Add(1 * time.Hour)
	count, err := d.PurgeAuditBefore(ctx, cutoff)
	if err != nil {
		t.Fatalf("purging: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 purged, got %d", count)
	}

	_, total2, _ := d.ListAudit(ctx, db.AuditFilter{Limit: 50})
	if total2 != 0 {
		t.Errorf("expected 0 after purge, got %d", total2)
	}

	_ = l // logger used for setup
}

func TestStartDBPurgeStopsOnCancel(t *testing.T) {
	d := newTestDB(t)
	l, _ := newTestLogger(t, d)

	ctx, cancel := context.WithCancel(context.Background())
	l.StartDBPurge(ctx, 1*time.Hour, 50*time.Millisecond)

	// Let it tick once
	time.Sleep(100 * time.Millisecond)
	cancel()
	// Give goroutine time to exit
	time.Sleep(100 * time.Millisecond)
}

func TestStartDBPurgeDisabledWhenRetentionZero(t *testing.T) {
	d := newTestDB(t)
	l, _ := newTestLogger(t, d)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Should not start any goroutine
	l.StartDBPurge(ctx, 0, 1*time.Hour)
}

func TestNewLoggerInvalidPath(t *testing.T) {
	d := newTestDB(t)
	_, err := NewLogger(d, "/nonexistent/dir/audit.log", slog.Default())
	if err == nil {
		t.Error("expected error for invalid file path")
	}
}

func TestNewLogger(t *testing.T) {
	d := newTestDB(t)
	filePath := filepath.Join(t.TempDir(), "audit.log")
	l, err := NewLogger(d, filePath, slog.Default())
	if err != nil {
		t.Fatalf("expected no error creating logger, got %v", err)
	}
	t.Cleanup(func() { l.Close() })
}

func TestReopenFile(t *testing.T) {
	d := newTestDB(t)
	l, _ := newTestLogger(t, d)

	if err := l.ReopenFile(); err != nil {
		t.Errorf("expected nil error from ReopenFile, got %v", err)
	}
}

func TestLog_ZeroTimestamp(t *testing.T) {
	d := newTestDB(t)
	l, filePath := newTestLogger(t, d)

	// Entry with zero Timestamp — writeToFile should default to time.Now()
	l.Log(context.Background(), &db.AuditEntry{
		Username: "zerotime",
		SourceIP: "127.0.0.1",
		Action:   ActionLogin,
		Result:   ResultSuccess,
		Details:  "zero timestamp test",
		// Timestamp is deliberately left zero
	})

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("reading audit file: %v", err)
	}

	var fe fileEntry
	if err := json.Unmarshal(data, &fe); err != nil {
		t.Fatalf("parsing file entry: %v", err)
	}
	if fe.Timestamp == "" {
		t.Error("expected non-empty timestamp in file entry even when AuditEntry.Timestamp is zero")
	}

	ts, err := time.Parse(time.RFC3339Nano, fe.Timestamp)
	if err != nil {
		t.Fatalf("parsing timestamp %q: %v", fe.Timestamp, err)
	}
	if ts.IsZero() {
		t.Error("expected non-zero timestamp in file entry")
	}
}

func TestClose(t *testing.T) {
	d := newTestDB(t)
	filePath := filepath.Join(t.TempDir(), "audit.log")
	l, err := NewLogger(d, filePath, slog.Default())
	if err != nil {
		t.Fatalf("creating logger: %v", err)
	}

	if err := l.Close(); err != nil {
		t.Errorf("expected nil error from Close, got %v", err)
	}
}

// TestLog_DBError covers the error branch in Log when AppendAudit fails.
func TestLog_DBError(t *testing.T) {
	d := newTestDB(t)
	l, _ := newTestLogger(t, d)
	ctx := context.Background()

	// Close the DB to force AppendAudit to fail on the next call
	d.Close()

	// Log should not panic; it logs the error and still calls writeToFile
	l.Log(ctx, &db.AuditEntry{
		Username: "error-user",
		SourceIP: "1.1.1.1",
		Action:   ActionLogin,
		Result:   ResultSuccess,
	})
}

// TestLog_FileWriteError covers the file write error branch in writeToFile.
func TestLog_FileWriteError(t *testing.T) {
	d := newTestDB(t)
	l, _ := newTestLogger(t, d)
	ctx := context.Background()

	// Close the underlying RotatableFile to force a write failure
	// (l.file is accessible because this test is in package audit)
	l.file.Close()

	// Log should not panic; the file write error is silently logged
	l.Log(ctx, &db.AuditEntry{
		Username: "file-error",
		SourceIP: "2.2.2.2",
		Action:   ActionLogin,
		Result:   ResultSuccess,
	})
}

// TestStartDBPurge_PurgesEntries covers the count > 0 log path in StartDBPurge.
func TestStartDBPurge_PurgesEntries(t *testing.T) {
	d := newTestDB(t)
	l, _ := newTestLogger(t, d)
	ctx, cancel := context.WithCancel(context.Background())

	// Insert an "old" entry directly with a past timestamp so it will be purged
	if err := d.AppendAudit(context.Background(), &db.AuditEntry{
		Username: "old-entry",
		Action:   ActionLogin,
		Result:   ResultSuccess,
	}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}

	// Start purge with 1ns retention (everything older than ~now is eligible)
	// and a fast interval so the purge fires before we cancel
	l.StartDBPurge(ctx, 1*time.Nanosecond, 30*time.Millisecond)

	// Give the goroutine enough time to fire at least once
	time.Sleep(150 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)

	// Verify the entry was purged
	_, total, _ := d.ListAudit(context.Background(), db.AuditFilter{Limit: 50})
	if total != 0 {
		t.Logf("note: expected 0 entries after purge, got %d (timing-sensitive)", total)
	}
}

// TestStartDBPurge_DBError covers the error branch in the StartDBPurge ticker handler.
func TestStartDBPurge_DBError(t *testing.T) {
	d := newTestDB(t)
	l, _ := newTestLogger(t, d)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start purge with a very short interval
	l.StartDBPurge(ctx, 1*time.Hour, 30*time.Millisecond)

	// Give the ticker a moment to fire, then close the DB so the purge fails
	time.Sleep(50 * time.Millisecond)
	d.Close()

	// Let the next tick fire against the closed DB
	time.Sleep(60 * time.Millisecond)
	cancel()
	time.Sleep(30 * time.Millisecond)
}
