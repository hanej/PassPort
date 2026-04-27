package emailotp

// security_test.go contains security-focused tests for the email OTP client:
// randomness, zero-padding correctness, and resistance to malformed input.

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hanej/passport/internal/mfa"
)

func secTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func newSecTestClient(length int) *Client {
	return New(mfa.EmailOTPConfig{OTPLength: length, OTPTTLMinutes: 5}, secTestLogger())
}

// ---------------------------------------------------------------------------
// Randomness and uniqueness
// ---------------------------------------------------------------------------

// TestOTP_Randomness calls Initiate 100 times and verifies all generated codes
// are distinct. A collision would indicate non-random or sequential generation.
// Uses 8 digits (100M possibilities) instead of 6 to minimize birthday paradox collisions.
func TestOTP_Randomness(t *testing.T) {
	client := newSecTestClient(8)
	seen := make(map[string]struct{}, 100)

	for i := range 100 {
		_, state, err := client.Initiate(context.Background(), "")
		if err != nil {
			t.Fatalf("Initiate failed on iteration %d: %v", i, err)
		}
		code := ExtractCode(state)
		if code == "" {
			t.Fatalf("iteration %d: empty code in state %q", i, state)
		}
		if _, dup := seen[code]; dup {
			t.Errorf("duplicate OTP code %q detected after %d iterations — non-random generation", code, i)
		}
		seen[code] = struct{}{}
	}
}

// TestOTP_AllDigits verifies that all generated codes consist exclusively of
// decimal digits (0-9), confirming no alphabet or special characters slip in.
func TestOTP_AllDigits(t *testing.T) {
	client := newSecTestClient(6)

	for i := range 50 {
		_, state, err := client.Initiate(context.Background(), "")
		if err != nil {
			t.Fatalf("Initiate failed on iteration %d: %v", i, err)
		}
		code := ExtractCode(state)
		for _, ch := range code {
			if ch < '0' || ch > '9' {
				t.Errorf("code %q contains non-digit character %q", code, ch)
			}
		}
	}
}

// TestOTP_LengthRespected verifies that generated codes are exactly OTPLength
// characters long (zero-padded when necessary).
func TestOTP_LengthRespected(t *testing.T) {
	for _, length := range []int{4, 6, 8} {
		t.Run(fmt.Sprintf("length=%d", length), func(t *testing.T) {
			client := newSecTestClient(length)
			for i := range 20 {
				_, state, err := client.Initiate(context.Background(), "")
				if err != nil {
					t.Fatalf("iteration %d: %v", i, err)
				}
				code := ExtractCode(state)
				if len(code) != length {
					t.Errorf("expected code length %d, got %d (code=%q)", length, len(code), code)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Zero-padding correctness
// ---------------------------------------------------------------------------

// TestOTP_ZeroPaddingIsSignificant verifies that the zero-padded code "000042"
// and the non-padded string "42" are treated as distinct values.
// This guards against accidental integer-comparison short-circuits.
func TestOTP_ZeroPaddingIsSignificant(t *testing.T) {
	client := newSecTestClient(6)

	// Construct a state with a known small code value ("000042").
	expiry := time.Now().Add(5 * time.Minute).Unix()
	paddedCode := "000042"
	state := fmt.Sprintf("otp:%s:%d", paddedCode, expiry)

	// Correct padded code must pass.
	if err := client.Verify(context.Background(), paddedCode, state, ""); err != nil {
		t.Errorf("expected padded code %q to pass, got: %v", paddedCode, err)
	}

	// Unpadded string "42" must fail — byte comparison, not integer comparison.
	if err := client.Verify(context.Background(), "42", state, ""); err == nil {
		t.Error("expected unpadded code '42' to fail against padded stored code '000042'")
	}
}

// ---------------------------------------------------------------------------
// Expiry boundary conditions
// ---------------------------------------------------------------------------

// TestOTP_ExpiryBoundary verifies exact second boundary behavior:
// a code with expiry = now-1 is rejected (expired), while expiry = now+1 passes.
func TestOTP_ExpiryBoundary(t *testing.T) {
	client := newSecTestClient(6)

	// Just-expired: expiry is one second in the past.
	pastExpiry := time.Now().Add(-1 * time.Second).Unix()
	expiredState := fmt.Sprintf("otp:123456:%d", pastExpiry)
	if err := client.Verify(context.Background(), "123456", expiredState, ""); err == nil {
		t.Error("expected error for just-expired OTP (1s in past), got nil")
	}

	// Still valid: expiry is one second in the future.
	futureExpiry := time.Now().Add(1 * time.Second).Unix()
	validState := fmt.Sprintf("otp:123456:%d", futureExpiry)
	if err := client.Verify(context.Background(), "123456", validState, ""); err != nil {
		t.Errorf("expected no error for OTP expiring in 1s, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Malformed state resistance
// ---------------------------------------------------------------------------

// TestOTP_MalformedStates verifies that Verify returns an error for every
// malformed or crafted state string an attacker might supply.
func TestOTP_MalformedStates(t *testing.T) {
	client := newSecTestClient(6)
	validExpiry := fmt.Sprintf("%d", time.Now().Add(5*time.Minute).Unix())

	cases := []struct {
		name  string
		code  string
		state string
	}{
		{"empty state", "123456", ""},
		{"wrong prefix", "123456", "totp:123456:" + validExpiry},
		{"missing expiry", "123456", "otp:123456"},
		{"extra colons", "123456", "otp:123456:extra:" + validExpiry},
		{"non-numeric expiry", "123456", "otp:123456:notanumber"},
		{"negative expiry", "123456", "otp:123456:-1"},
		{"unicode in state", "123456", "otp:123456:" + validExpiry + string([]rune{0xfffd})},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := client.Verify(context.Background(), tc.code, tc.state, ""); err == nil {
				t.Errorf("expected error for malformed state %q, got nil", tc.state)
			}
		})
	}
}

// TestOTP_LeadingTrailingWhitespace verifies that codes with surrounding
// whitespace are NOT accepted — the comparison is byte-exact.
func TestOTP_LeadingTrailingWhitespace(t *testing.T) {
	client := newSecTestClient(6)

	expiry := time.Now().Add(5 * time.Minute).Unix()
	state := fmt.Sprintf("otp:123456:%d", expiry)

	whitespaceVariants := []string{" 123456", "123456 ", " 123456 ", "\t123456", "123456\n"}
	for _, code := range whitespaceVariants {
		if err := client.Verify(context.Background(), code, state, ""); err == nil {
			t.Errorf("expected error for code with whitespace %q, got nil", code)
		}
	}
}

// ---------------------------------------------------------------------------
// Constant-time comparison documentation test
// ---------------------------------------------------------------------------

// TestOTP_ConstantTimeCompareUsed is a code-review assertion: Verify must use
// subtle.ConstantTimeCompare to prevent timing-based OTP oracle attacks.
// This test reads the source and fails if the usage is removed.
func TestOTP_ConstantTimeCompareUsed(t *testing.T) {
	// Read the source file and verify subtle.ConstantTimeCompare is present.
	// This is a static analysis test — it ensures the timing-safe comparison
	// is not accidentally replaced with a direct string equality check.
	src, err := os.ReadFile("client.go")
	if err != nil {
		t.Fatalf("could not read client.go: %v", err)
	}
	if !strings.Contains(string(src), "subtle.ConstantTimeCompare") {
		t.Error("client.go must use subtle.ConstantTimeCompare for OTP comparison — do not replace with == or strings.Compare")
	}
}
