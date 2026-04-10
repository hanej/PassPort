// Copyright 2026 Jason Hane
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
)

// ---- test helpers ----

func testDB(t *testing.T) *db.DB {
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

func testCrypto(t *testing.T) *crypto.Service {
	t.Helper()
	key := make([]byte, 32) // known-zero test key — never used for real data
	svc, err := crypto.NewService(key, 1)
	if err != nil {
		t.Fatalf("creating crypto service: %v", err)
	}
	return svc
}

func createAdmin(t *testing.T, database *db.DB, username string) {
	t.Helper()
	hash, err := auth.HashPassword("test-password")
	if err != nil {
		t.Fatalf("hashing password: %v", err)
	}
	if _, err := database.CreateLocalAdmin(context.Background(), username, hash); err != nil {
		t.Fatalf("creating admin: %v", err)
	}
}

// mockAdminStore lets tests inject errors into individual DB operations.
type mockAdminStore struct {
	admin      *db.LocalAdmin
	getErr     error
	updateErr  error
	historyErr error
}

func (m *mockAdminStore) GetLocalAdmin(_ context.Context, _ string) (*db.LocalAdmin, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if m.admin != nil {
		return m.admin, nil
	}
	return nil, db.ErrNotFound
}

func (m *mockAdminStore) UpdateLocalAdminPassword(_ context.Context, _, _ string, _ bool) error {
	return m.updateErr
}

func (m *mockAdminStore) AddPasswordHistory(_ context.Context, _, _ string, _ int) error {
	return m.historyErr
}

// ---- -version ----

// TestVersionDev verifies the package-level version var has a value.
// The binary prints this with -version; the default for development builds is "dev".
func TestVersionDev(t *testing.T) {
	if version == "" {
		t.Error("version var must not be empty")
	}
}

// TestVersionFlag builds the binary and runs it with -version, verifying it
// exits 0 and prints a non-empty string.
func TestVersionFlag(t *testing.T) {
	// Build a temporary binary so we can test the real flag behaviour.
	dir := t.TempDir()
	bin := filepath.Join(dir, "passport")
	build := exec.Command("go", "build", "-o", bin, "./cmd/passport")
	build.Dir = findModuleRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	cmd := exec.Command(bin, "-version")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("-version exited non-zero: %v", err)
	}
	if strings.TrimSpace(string(out)) == "" {
		t.Error("expected non-empty output for -version")
	}
}

// findModuleRoot walks up from the test binary location to find the go.mod root.
func findModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod")
		}
		dir = parent
	}
}

// ---- -reset-admin-password ----

func TestRunResetAdminPassword_Success(t *testing.T) {
	database := testDB(t)
	createAdmin(t, database, "admin")

	var out bytes.Buffer
	pw, err := runResetAdminPassword(context.Background(), database, "admin", 14, &out, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pw == "" {
		t.Error("expected non-empty returned password")
	}
	if len(pw) < 20 {
		t.Errorf("expected password length >= 20, got %d", len(pw))
	}

	output := out.String()
	if !strings.Contains(output, `"admin"`) {
		t.Errorf("expected username in output, got: %s", output)
	}
	if !strings.Contains(output, pw) {
		t.Errorf("expected new password in output, got: %s", output)
	}
	if !strings.Contains(output, "flagged") {
		t.Errorf("expected 'flagged' message in output, got: %s", output)
	}

	// DB state: must_change_password should be set and hash should match password.
	admin, err := database.GetLocalAdmin(context.Background(), "admin")
	if err != nil {
		t.Fatalf("getting admin: %v", err)
	}
	if !admin.MustChangePassword {
		t.Error("expected must_change_password=true after reset")
	}
	if err := auth.CheckPassword(admin.PasswordHash, pw); err != nil {
		t.Error("stored hash does not match the returned plaintext password")
	}

	// History should contain the new hash.
	hashes, err := database.GetPasswordHistory(context.Background(), "admin")
	if err != nil {
		t.Fatalf("getting history: %v", err)
	}
	if len(hashes) == 0 {
		t.Error("expected at least one history entry after reset")
	}
}

func TestRunResetAdminPassword_NotFound(t *testing.T) {
	database := testDB(t)

	_, err := runResetAdminPassword(context.Background(), database, "nobody", 14, &bytes.Buffer{}, nil)
	if err == nil {
		t.Fatal("expected error for nonexistent admin")
	}
}

func TestRunResetAdminPassword_UpdateError(t *testing.T) {
	mock := &mockAdminStore{
		admin:     &db.LocalAdmin{Username: "admin"},
		updateErr: errors.New("db write failed"),
	}

	_, err := runResetAdminPassword(context.Background(), mock, "admin", 14, &bytes.Buffer{}, nil)
	if err == nil {
		t.Fatal("expected error when UpdateLocalAdminPassword fails")
	}
}

func TestRunResetAdminPassword_HistoryWarn(t *testing.T) {
	// History errors are non-fatal (logged as warn, not returned).
	mock := &mockAdminStore{
		admin:      &db.LocalAdmin{Username: "admin"},
		historyErr: errors.New("history write failed"),
	}

	_, err := runResetAdminPassword(context.Background(), mock, "admin", 14, &bytes.Buffer{}, nil)
	if err != nil {
		t.Fatalf("history error should not be returned: %v", err)
	}
}

// ---- -force-password-change ----

func TestRunForcePasswordChange_Success(t *testing.T) {
	database := testDB(t)
	createAdmin(t, database, "admin")

	var out bytes.Buffer
	if err := runForcePasswordChange(context.Background(), database, "admin", &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	admin, err := database.GetLocalAdmin(context.Background(), "admin")
	if err != nil {
		t.Fatalf("getting admin: %v", err)
	}
	if !admin.MustChangePassword {
		t.Error("expected must_change_password=true after force-password-change")
	}
	// Password itself should be unchanged.
	if err := auth.CheckPassword(admin.PasswordHash, "test-password"); err != nil {
		t.Error("password should not have changed")
	}
	if !strings.Contains(out.String(), `"admin"`) {
		t.Errorf("expected username in output, got: %s", out.String())
	}
}

func TestRunForcePasswordChange_NotFound(t *testing.T) {
	database := testDB(t)

	if err := runForcePasswordChange(context.Background(), database, "nobody", &bytes.Buffer{}); err == nil {
		t.Fatal("expected error for nonexistent admin")
	}
}

func TestRunForcePasswordChange_UpdateError(t *testing.T) {
	mock := &mockAdminStore{
		admin:     &db.LocalAdmin{Username: "admin", PasswordHash: "hash"},
		updateErr: errors.New("db write failed"),
	}

	if err := runForcePasswordChange(context.Background(), mock, "admin", &bytes.Buffer{}); err == nil {
		t.Fatal("expected error when UpdateLocalAdminPassword fails")
	}
}

// ---- -export / -backup / -import ----

func TestRunExport(t *testing.T) {
	database := testDB(t)
	cryptoSvc := testCrypto(t)
	outPath := filepath.Join(t.TempDir(), "export.json")

	if err := runExport(context.Background(), database, cryptoSvc, outPath); err != nil {
		t.Fatalf("runExport: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading export file: %v", err)
	}
	if !bytes.Contains(data, []byte("{")) {
		t.Error("expected JSON content in export file")
	}
	// File should not be world-readable.
	info, _ := os.Stat(outPath)
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("export file permissions too open: %o", info.Mode().Perm())
	}
}

func TestRunExport_BadPath(t *testing.T) {
	database := testDB(t)
	cryptoSvc := testCrypto(t)

	err := runExport(context.Background(), database, cryptoSvc, "/nonexistent/dir/export.json")
	if err == nil {
		t.Fatal("expected error for unwritable path")
	}
}

func TestRunBackup(t *testing.T) {
	database := testDB(t)
	outPath := filepath.Join(t.TempDir(), "backup.json")

	if err := runBackup(context.Background(), database, outPath); err != nil {
		t.Fatalf("runBackup: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading backup file: %v", err)
	}
	if !bytes.Contains(data, []byte("{")) {
		t.Error("expected JSON content in backup file")
	}
}

func TestRunBackup_BadPath(t *testing.T) {
	database := testDB(t)

	if err := runBackup(context.Background(), database, "/nonexistent/dir/backup.json"); err == nil {
		t.Fatal("expected error for unwritable path")
	}
}

func TestRunImport_RoundTrip(t *testing.T) {
	src := testDB(t)
	dst := testDB(t)
	cryptoSvc := testCrypto(t)

	outPath := filepath.Join(t.TempDir(), "export.json")
	if err := runExport(context.Background(), src, cryptoSvc, outPath); err != nil {
		t.Fatalf("runExport: %v", err)
	}

	result, err := runImport(context.Background(), dst, cryptoSvc, outPath)
	if err != nil {
		t.Fatalf("runImport: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestRunImport_MissingFile(t *testing.T) {
	database := testDB(t)
	cryptoSvc := testCrypto(t)

	if _, err := runImport(context.Background(), database, cryptoSvc, "/nonexistent/file.json"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestRunImport_InvalidJSON(t *testing.T) {
	database := testDB(t)
	cryptoSvc := testCrypto(t)

	badFile := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badFile, []byte("{not valid json"), 0600); err != nil {
		t.Fatalf("writing bad file: %v", err)
	}

	if _, err := runImport(context.Background(), database, cryptoSvc, badFile); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
