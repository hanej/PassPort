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
func (e *errAdminStore) AddPasswordHistory(ctx context.Context, username, passwordHash string, keepN int) error {
	return nil
}
func (e *errAdminStore) GetPasswordHistory(ctx context.Context, username string) ([]string, error) {
	return nil, nil
}

func TestBootstrap_GetAdminError(t *testing.T) {
	// When GetLocalAdmin returns a non-ErrNotFound error, Bootstrap should return that error.
	store := &errAdminStore{}
	logger := slog.Default()

	_, err := Bootstrap(context.Background(), store, 14, logger)
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
func (e *errCreateAdminStore) AddPasswordHistory(ctx context.Context, username, passwordHash string, keepN int) error {
	return nil
}
func (e *errCreateAdminStore) GetPasswordHistory(ctx context.Context, username string) ([]string, error) {
	return nil, nil
}

func TestBootstrap_CreateAdminError(t *testing.T) {
	store := &errCreateAdminStore{}
	_, err := Bootstrap(context.Background(), store, 14, slog.Default())
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

	password, err := Bootstrap(context.Background(), d, 14, logger)
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
	_, err := Bootstrap(context.Background(), d, 14, logger)
	if err != nil {
		t.Fatalf("first Bootstrap: %v", err)
	}

	// Second call should return empty string.
	password, err := Bootstrap(context.Background(), d, 14, logger)
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

	_, err := Bootstrap(context.Background(), d, 14, logger)
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

// TestHashPassword_TooLong verifies that HashPassword returns an error when the
// password exceeds bcrypt's 72-byte maximum.
func TestHashPassword_TooLong(t *testing.T) {
	long := strings.Repeat("x", 73)
	_, err := HashPassword(long)
	if err == nil {
		t.Fatal("expected error for password exceeding bcrypt's 72-byte limit")
	}
}

// ---- Password policy tests ----

func TestValidatePasswordPolicy_AllConstraintsMet(t *testing.T) {
	policy := PasswordPolicy{
		MinLength:        12,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireDigit:     true,
		RequireSpecial:   true,
	}
	if err := ValidatePasswordPolicy("Secure1Pass!", policy); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestValidatePasswordPolicy_TooShort(t *testing.T) {
	policy := PasswordPolicy{MinLength: 12}
	if err := ValidatePasswordPolicy("short", policy); err == nil {
		t.Error("expected error for short password")
	}
}

func TestValidatePasswordPolicy_MissingUppercase(t *testing.T) {
	policy := PasswordPolicy{MinLength: 1, RequireUppercase: true}
	if err := ValidatePasswordPolicy("nouppercase1!", policy); err == nil {
		t.Error("expected error for missing uppercase")
	}
}

func TestValidatePasswordPolicy_MissingLowercase(t *testing.T) {
	policy := PasswordPolicy{MinLength: 1, RequireLowercase: true}
	if err := ValidatePasswordPolicy("NOLOWERCASE1!", policy); err == nil {
		t.Error("expected error for missing lowercase")
	}
}

func TestValidatePasswordPolicy_MissingDigit(t *testing.T) {
	policy := PasswordPolicy{MinLength: 1, RequireDigit: true}
	if err := ValidatePasswordPolicy("NoDigitHere!", policy); err == nil {
		t.Error("expected error for missing digit")
	}
}

func TestValidatePasswordPolicy_MissingSpecial(t *testing.T) {
	policy := PasswordPolicy{MinLength: 1, RequireSpecial: true}
	if err := ValidatePasswordPolicy("NoSpecial1A", policy); err == nil {
		t.Error("expected error for missing special character")
	}
}

func TestValidatePasswordPolicy_EmptyPolicyAlwaysPasses(t *testing.T) {
	policy := PasswordPolicy{MinLength: 1}
	if err := ValidatePasswordPolicy("x", policy); err != nil {
		t.Errorf("empty policy should accept any non-empty password: %v", err)
	}
}

// ---- Password history tests ----

func TestCheckPasswordHistory_NoMatch(t *testing.T) {
	h1, _ := HashPassword("oldpass1")
	h2, _ := HashPassword("oldpass2")
	if err := CheckPasswordHistory("newpass", []string{h1, h2}); err != nil {
		t.Errorf("expected nil for new password, got %v", err)
	}
}

func TestCheckPasswordHistory_Match(t *testing.T) {
	h1, _ := HashPassword("reused")
	if err := CheckPasswordHistory("reused", []string{h1}); err == nil {
		t.Error("expected error when password matches history")
	}
}

func TestCheckPasswordHistory_EmptyHistory(t *testing.T) {
	if err := CheckPasswordHistory("anything", nil); err != nil {
		t.Errorf("empty history should never block: %v", err)
	}
}

func TestAddAndGetPasswordHistory(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	// Seed an admin so the FK is satisfied.
	hash, _ := HashPassword("initial")
	if _, err := d.CreateLocalAdmin(ctx, "admin", hash); err != nil {
		t.Fatalf("CreateLocalAdmin: %v", err)
	}

	// Add a few passwords.
	for i, pw := range []string{"pass1", "pass2", "pass3"} {
		h, _ := HashPassword(pw)
		if err := d.AddPasswordHistory(ctx, "admin", h, 10); err != nil {
			t.Fatalf("AddPasswordHistory[%d]: %v", i, err)
		}
	}

	hashes, err := d.GetPasswordHistory(ctx, "admin")
	if err != nil {
		t.Fatalf("GetPasswordHistory: %v", err)
	}
	if len(hashes) != 3 {
		t.Errorf("expected 3 history entries, got %d", len(hashes))
	}
}

func TestPasswordHistoryTrimming(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	hash, _ := HashPassword("initial")
	if _, err := d.CreateLocalAdmin(ctx, "admin", hash); err != nil {
		t.Fatalf("CreateLocalAdmin: %v", err)
	}

	// Add 5 entries but keep only 3.
	for i := 0; i < 5; i++ {
		h, _ := HashPassword(fmt.Sprintf("pass%d", i))
		if err := d.AddPasswordHistory(ctx, "admin", h, 3); err != nil {
			t.Fatalf("AddPasswordHistory[%d]: %v", i, err)
		}
	}

	hashes, err := d.GetPasswordHistory(ctx, "admin")
	if err != nil {
		t.Fatalf("GetPasswordHistory: %v", err)
	}
	if len(hashes) != 3 {
		t.Errorf("expected 3 history entries after trimming, got %d", len(hashes))
	}
}

func TestBootstrapRecordsInitialHistory(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	_, err := Bootstrap(ctx, d, 14, slog.Default())
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	hashes, err := d.GetPasswordHistory(ctx, "admin")
	if err != nil {
		t.Fatalf("GetPasswordHistory: %v", err)
	}
	if len(hashes) != 1 {
		t.Errorf("expected 1 history entry after bootstrap, got %d", len(hashes))
	}
}
