package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/hanej/passport/internal/db"
)

// passwordCharset is the set of characters used for random password generation.
const passwordCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"

// specialChars is the set recognised as "special" for policy enforcement.
const specialChars = "!@#$%^&*()-_=+[]{}|;:',.<>?/`~\"\\"

// PasswordPolicy defines the complexity and history requirements for local admin passwords.
type PasswordPolicy struct {
	MinLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireDigit     bool
	RequireSpecial   bool
	// HistoryLen is how many previous password hashes to keep to prevent reuse.
	HistoryLen int
}

// ValidatePasswordPolicy returns an error describing the first unmet policy constraint,
// or nil if the password satisfies all constraints.
func ValidatePasswordPolicy(password string, policy PasswordPolicy) error {
	if len(password) < policy.MinLength {
		return fmt.Errorf("password must be at least %d characters long", policy.MinLength)
	}
	if policy.RequireUppercase && !strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if policy.RequireLowercase && !strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz") {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if policy.RequireDigit && !strings.ContainsAny(password, "0123456789") {
		return fmt.Errorf("password must contain at least one digit")
	}
	if policy.RequireSpecial && !strings.ContainsAny(password, specialChars) {
		return fmt.Errorf("password must contain at least one special character")
	}
	return nil
}

// CheckPasswordHistory returns an error if newPassword matches any of the supplied
// bcrypt hashes (i.e. the password has been used recently).
func CheckPasswordHistory(newPassword string, hashes []string) error {
	for _, h := range hashes {
		if err := bcrypt.CompareHashAndPassword([]byte(h), []byte(newPassword)); err == nil {
			return fmt.Errorf("password has been used recently and cannot be reused")
		}
	}
	return nil
}

// HashPassword hashes a password using bcrypt with default cost.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hashing password: %w", err)
	}
	return string(hash), nil
}

// CheckPassword compares a password against a bcrypt hash using constant-time comparison.
func CheckPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// GenerateRandomPassword generates a cryptographically random password of the given length.
// Uses crypto/rand with alphanumeric + special characters.
func GenerateRandomPassword(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("password length must be positive")
	}

	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}

	charset := []byte(passwordCharset)
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}

	return string(b), nil
}

// GeneratePasswordWithPolicy generates a cryptographically random password using
// the supplied character-class flags and explicit special-character set. Digits,
// lowercase, and uppercase are each included only when their flag is true.
// specialChars is appended verbatim; pass an empty string to exclude specials.
// Returns an error if the resulting charset is empty or length is not positive.
func GeneratePasswordWithPolicy(length int, allowUpper, allowLower, allowDigits bool, specialChars string) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("password length must be positive")
	}

	var charset string
	if allowDigits {
		charset += "0123456789"
	}
	if allowLower {
		charset += "abcdefghijklmnopqrstuvwxyz"
	}
	if allowUpper {
		charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	charset += specialChars

	if len(charset) == 0 {
		return "", fmt.Errorf("password charset is empty: all character classes are disabled")
	}

	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}

	cs := []byte(charset)
	for i := range b {
		b[i] = cs[int(b[i])%len(cs)]
	}

	return string(b), nil
}

// Bootstrap checks if a local admin exists, creates one if not.
// Returns the generated password (only on first creation) or empty string if already exists.
// keepHistoryN controls how many history entries to retain (passed to AddPasswordHistory).
func Bootstrap(ctx context.Context, store db.AdminStore, keepHistoryN int, logger *slog.Logger) (string, error) {
	_, err := store.GetLocalAdmin(ctx, "admin")
	if err == nil {
		// Admin already exists.
		logger.Info("local admin already exists, skipping bootstrap")
		return "", nil
	}

	if !errors.Is(err, db.ErrNotFound) {
		return "", fmt.Errorf("checking for local admin: %w", err)
	}

	// Admin does not exist; create one.
	password, err := GenerateRandomPassword(24)
	if err != nil {
		return "", fmt.Errorf("generating bootstrap password: %w", err)
	}

	hash, err := HashPassword(password)
	if err != nil {
		return "", fmt.Errorf("hashing bootstrap password: %w", err)
	}

	if _, err := store.CreateLocalAdmin(ctx, "admin", hash); err != nil {
		return "", fmt.Errorf("creating bootstrap admin: %w", err)
	}

	// Record the initial hash in history so it cannot be immediately reused.
	if err := store.AddPasswordHistory(ctx, "admin", hash, keepHistoryN); err != nil {
		logger.Warn("failed to record initial password history", "error", err)
	}

	logger.Info("local admin created", slog.String("username", "admin"))
	return password, nil
}
