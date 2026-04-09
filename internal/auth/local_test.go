package auth

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/hanej/passport/internal/db"
)

// errAdminStore is a minimal AdminStore whose GetLocalAdmin returns a non-ErrNotFound error.
type errAdminStore struct{}

func (e *errAdminStore) GetLocalAdmin(ctx context.Context, username string) (*db.LocalAdmin, error) {
	return nil, fmt.Errorf("database connection lost")
}
func (e *errAdminStore) CreateLocalAdmin(ctx context.Context, username, passwordHash string) (*db.LocalAdmin, error) {
	return nil, nil
}
func (e *errAdminStore) UpdateLocalAdminPassword(ctx context.Context, username, passwordHash string, mustChange bool) error {
	return nil
}
func (e *errAdminStore) ListLocalAdmins(ctx context.Context) ([]db.LocalAdmin, error) {
	return nil, nil
}

func TestBootstrap_GetAdminError(t *testing.T) {
	// When GetLocalAdmin returns a non-ErrNotFound error, Bootstrap should return that error.
	store := &errAdminStore{}
	logger := slog.Default()

	_, err := Bootstrap(context.Background(), store, logger)
	if err == nil {
		t.Fatal("expected error when GetLocalAdmin fails with unknown error")
	}
}

// errCreateAdminStore is an AdminStore whose GetLocalAdmin returns ErrNotFound
// (so Bootstrap proceeds) but CreateLocalAdmin returns an error.
type errCreateAdminStore struct{}

func (e *errCreateAdminStore) GetLocalAdmin(ctx context.Context, username string) (*db.LocalAdmin, error) {
	return nil, db.ErrNotFound
}
func (e *errCreateAdminStore) CreateLocalAdmin(ctx context.Context, username, passwordHash string) (*db.LocalAdmin, error) {
	return nil, fmt.Errorf("create admin failed: disk full")
}
func (e *errCreateAdminStore) UpdateLocalAdminPassword(ctx context.Context, username, passwordHash string, mustChange bool) error {
	return nil
}
func (e *errCreateAdminStore) ListLocalAdmins(ctx context.Context) ([]db.LocalAdmin, error) {
	return nil, nil
}

func TestBootstrap_CreateAdminError(t *testing.T) {
	store := &errCreateAdminStore{}
	_, err := Bootstrap(context.Background(), store, slog.Default())
	if err == nil {
		t.Fatal("expected error when CreateLocalAdmin fails")
	}
}

func TestHashPasswordAndCheckPassword(t *testing.T) {
	password := "correct-horse-battery-staple"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if err := CheckPassword(hash, password); err != nil {
		t.Fatalf("CheckPassword should succeed for correct password: %v", err)
	}
}

func TestCheckPasswordWrongPassword(t *testing.T) {
	hash, err := HashPassword("real-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if err := CheckPassword(hash, "wrong-password"); err == nil {
		t.Fatal("CheckPassword should fail for wrong password")
	}
}

func TestGenerateRandomPasswordLength(t *testing.T) {
	for _, length := range []int{8, 16, 24, 32} {
		pw, err := GenerateRandomPassword(length)
		if err != nil {
			t.Fatalf("GenerateRandomPassword(%d): %v", length, err)
		}
		if len(pw) != length {
			t.Errorf("GenerateRandomPassword(%d) produced length %d", length, len(pw))
		}
	}
}

func TestGenerateRandomPasswordUniqueness(t *testing.T) {
	pw1, err := GenerateRandomPassword(24)
	if err != nil {
		t.Fatalf("GenerateRandomPassword: %v", err)
	}

	pw2, err := GenerateRandomPassword(24)
	if err != nil {
		t.Fatalf("GenerateRandomPassword: %v", err)
	}

	if pw1 == pw2 {
		t.Error("two generated passwords should differ")
	}
}

func TestBootstrapCreatesAdmin(t *testing.T) {
	d := newTestDB(t)
	logger := slog.Default()

	password, err := Bootstrap(context.Background(), d, logger)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if password == "" {
		t.Fatal("expected non-empty password on first bootstrap")
	}
	if len(password) != 24 {
		t.Errorf("expected 24-char password, got %d", len(password))
	}

	// Verify admin exists in DB.
	admin, err := d.GetLocalAdmin(context.Background(), "admin")
	if err != nil {
		t.Fatalf("GetLocalAdmin: %v", err)
	}

	// Verify the returned password matches the stored hash.
	if err := CheckPassword(admin.PasswordHash, password); err != nil {
		t.Fatalf("stored hash does not match generated password: %v", err)
	}
}

func TestBootstrapReturnEmptyOnSecondCall(t *testing.T) {
	d := newTestDB(t)
	logger := slog.Default()

	// First call creates the admin.
	_, err := Bootstrap(context.Background(), d, logger)
	if err != nil {
		t.Fatalf("first Bootstrap: %v", err)
	}

	// Second call should return empty string.
	password, err := Bootstrap(context.Background(), d, logger)
	if err != nil {
		t.Fatalf("second Bootstrap: %v", err)
	}
	if password != "" {
		t.Errorf("expected empty password on second call, got %q", password)
	}
}

func TestBootstrapSetsMustChangePassword(t *testing.T) {
	d := newTestDB(t)
	logger := slog.Default()

	_, err := Bootstrap(context.Background(), d, logger)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	admin, err := d.GetLocalAdmin(context.Background(), "admin")
	if err != nil {
		t.Fatalf("GetLocalAdmin: %v", err)
	}

	if !admin.MustChangePassword {
		t.Error("expected MustChangePassword to be true after bootstrap")
	}
}

func TestGeneratePasswordWithPolicy_Happy(t *testing.T) {
	pw, err := GeneratePasswordWithPolicy(12, true, true, true, "!@#")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pw) != 12 {
		t.Errorf("expected length 12, got %d", len(pw))
	}
}

func TestGeneratePasswordWithPolicy_DigitsOnly(t *testing.T) {
	pw, err := GeneratePasswordWithPolicy(8, false, false, true, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, c := range pw {
		if c < '0' || c > '9' {
			t.Errorf("expected digit-only password, got char %q", c)
		}
	}
}

func TestGeneratePasswordWithPolicy_EmptyCharset(t *testing.T) {
	_, err := GeneratePasswordWithPolicy(8, false, false, false, "")
	if err == nil {
		t.Fatal("expected error for empty charset")
	}
	if !strings.Contains(err.Error(), "charset is empty") {
		t.Errorf("expected 'charset is empty' in error, got %v", err)
	}
}

func TestGeneratePasswordWithPolicy_ZeroLength(t *testing.T) {
	_, err := GeneratePasswordWithPolicy(0, true, true, true, "")
	if err == nil {
		t.Fatal("expected error for zero length")
	}
	if !strings.Contains(err.Error(), "must be positive") {
		t.Errorf("expected 'must be positive' in error, got %v", err)
	}
}

func TestGeneratePasswordWithPolicy_NegativeLength(t *testing.T) {
	_, err := GeneratePasswordWithPolicy(-1, true, true, true, "")
	if err == nil {
		t.Fatal("expected error for negative length")
	}
}

func TestGenerateRandomPassword_ZeroLength(t *testing.T) {
	_, err := GenerateRandomPassword(0)
	if err == nil {
		t.Fatal("expected error for zero length")
	}
}

func TestGenerateRandomPassword_NegativeLength(t *testing.T) {
	_, err := GenerateRandomPassword(-5)
	if err == nil {
		t.Fatal("expected error for negative length")
	}
}

func TestGenerateRandomPassword_CharsetContents(t *testing.T) {
	pw, err := GenerateRandomPassword(100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pw) != 100 {
		t.Errorf("expected length 100, got %d", len(pw))
	}
	for _, c := range pw {
		if !strings.ContainsRune(passwordCharset, c) {
			t.Errorf("character %q not in charset", c)
		}
	}
}
