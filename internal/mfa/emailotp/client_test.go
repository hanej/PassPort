package emailotp

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

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNew_Defaults(t *testing.T) {
	// Zero-value config gets default values.
	c := New(mfa.EmailOTPConfig{}, testLogger())
	if c.OTPLength() != 6 {
		t.Errorf("expected default OTPLength 6, got %d", c.OTPLength())
	}
	if c.TTLMinutes() != 5 {
		t.Errorf("expected default TTLMinutes 5, got %d", c.TTLMinutes())
	}
	if c.EmailSubject() != "Your verification code" {
		t.Errorf("expected default subject, got %q", c.EmailSubject())
	}
}

func TestNew_CustomConfig(t *testing.T) {
	c := New(mfa.EmailOTPConfig{
		OTPLength:     8,
		OTPTTLMinutes: 10,
		EmailSubject:  "Your OTP",
	}, testLogger())
	if c.OTPLength() != 8 {
		t.Errorf("expected OTPLength 8, got %d", c.OTPLength())
	}
	if c.TTLMinutes() != 10 {
		t.Errorf("expected TTLMinutes 10, got %d", c.TTLMinutes())
	}
	if c.EmailSubject() != "Your OTP" {
		t.Errorf("expected 'Your OTP', got %q", c.EmailSubject())
	}
}

func TestType(t *testing.T) {
	c := New(mfa.EmailOTPConfig{}, testLogger())
	if c.Type() != mfa.ProviderTypeEmail {
		t.Errorf("expected ProviderTypeEmail, got %v", c.Type())
	}
}

func TestInitiate_GeneratesState(t *testing.T) {
	c := New(mfa.EmailOTPConfig{OTPLength: 6, OTPTTLMinutes: 5}, testLogger())
	authURL, state, err := c.Initiate(context.Background(), "jdoe")
	if err != nil {
		t.Fatalf("Initiate error: %v", err)
	}
	if authURL != "" {
		t.Errorf("expected empty authURL, got %q", authURL)
	}
	parts := strings.SplitN(state, ":", 3)
	if len(parts) != 3 || parts[0] != "otp" {
		t.Errorf("invalid state format: %q", state)
	}
	if len(parts[1]) != 6 {
		t.Errorf("expected 6-digit OTP, got %q", parts[1])
	}
}

func TestVerify_Valid(t *testing.T) {
	c := New(mfa.EmailOTPConfig{OTPLength: 6, OTPTTLMinutes: 5}, testLogger())
	_, state, _ := c.Initiate(context.Background(), "jdoe")
	code := ExtractCode(state)

	if err := c.Verify(context.Background(), code, state, "jdoe"); err != nil {
		t.Errorf("expected valid code to pass, got: %v", err)
	}
}

func TestVerify_InvalidCode(t *testing.T) {
	c := New(mfa.EmailOTPConfig{OTPLength: 6, OTPTTLMinutes: 5}, testLogger())
	_, state, _ := c.Initiate(context.Background(), "jdoe")

	err := c.Verify(context.Background(), "000000", state, "jdoe")
	if err == nil {
		t.Error("expected error for wrong code")
	}
}

func TestVerify_ExpiredState(t *testing.T) {
	c := New(mfa.EmailOTPConfig{OTPLength: 6, OTPTTLMinutes: 5}, testLogger())
	// Create an already-expired state.
	expiry := time.Now().Add(-1 * time.Minute).Unix()
	state := fmt.Sprintf("otp:123456:%d", expiry)

	err := c.Verify(context.Background(), "123456", state, "jdoe")
	if err == nil {
		t.Error("expected error for expired OTP")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected 'expired' in error, got: %v", err)
	}
}

func TestVerify_InvalidStateFormat(t *testing.T) {
	c := New(mfa.EmailOTPConfig{}, testLogger())

	tests := []string{
		"",
		"invalid",
		"otp:only-two",
		"notopt:123456:9999999999",
	}
	for _, state := range tests {
		if err := c.Verify(context.Background(), "123456", state, "jdoe"); err == nil {
			t.Errorf("expected error for invalid state %q", state)
		}
	}
}

func TestVerify_InvalidExpiry(t *testing.T) {
	c := New(mfa.EmailOTPConfig{}, testLogger())
	state := "otp:123456:not-a-number"
	if err := c.Verify(context.Background(), "123456", state, "jdoe"); err == nil {
		t.Error("expected error for invalid expiry")
	}
}

func TestHealthCheck(t *testing.T) {
	c := New(mfa.EmailOTPConfig{}, testLogger())
	if err := c.HealthCheck(context.Background()); err != nil {
		t.Errorf("expected nil from HealthCheck, got: %v", err)
	}
}

func TestExtractCode(t *testing.T) {
	tests := []struct {
		state string
		want  string
	}{
		{"otp:123456:9999999999", "123456"},
		{"otp:000042:1234567890", "000042"},
		{"invalid", ""},
		{"", ""},
		{"otp:only-two", ""},
		{"notopt:123456:9999", ""},
	}
	for _, tc := range tests {
		got := ExtractCode(tc.state)
		if got != tc.want {
			t.Errorf("ExtractCode(%q) = %q, want %q", tc.state, got, tc.want)
		}
	}
}

func TestGenerateOTP_Length(t *testing.T) {
	for _, n := range []int{4, 6, 8} {
		code, err := generateOTP(n)
		if err != nil {
			t.Errorf("generateOTP(%d) error: %v", n, err)
			continue
		}
		if len(code) != n {
			t.Errorf("generateOTP(%d) = %q, want length %d", n, code, n)
		}
	}
}

func TestIsStateValid_ValidNotExpired(t *testing.T) {
	// Create a state that expires in the future.
	expiry := time.Now().Add(5 * time.Minute).Unix()
	state := fmt.Sprintf("otp:123456:%d", expiry)
	if !IsStateValid(state) {
		t.Error("expected valid state to return true")
	}
}

func TestIsStateValid_Expired(t *testing.T) {
	// Create a state that expired 1 minute ago.
	expiry := time.Now().Add(-1 * time.Minute).Unix()
	state := fmt.Sprintf("otp:123456:%d", expiry)
	if IsStateValid(state) {
		t.Error("expected expired state to return false")
	}
}

func TestIsStateValid_EdgeCase_ExactExpiry(t *testing.T) {
	// Create a state that expires right now.
	expiry := time.Now().Unix()
	state := fmt.Sprintf("otp:123456:%d", expiry)
	// Should be valid (not strictly greater than, but <=)
	if !IsStateValid(state) {
		t.Error("expected state expiring now to return true")
	}
}

func TestIsStateValid_InvalidFormat(t *testing.T) {
	tests := []string{
		"",
		"invalid",
		"otp:only-two",
		"notopt:123456:9999999999",
		"otp:code:not-a-number",
	}
	for _, state := range tests {
		if IsStateValid(state) {
			t.Errorf("expected invalid state %q to return false", state)
		}
	}
}

func TestInitiate_InvalidOTPLength(t *testing.T) {
	// Test with custom OTP length to ensure Initiate creates valid state.
	c := New(mfa.EmailOTPConfig{OTPLength: 4, OTPTTLMinutes: 5}, testLogger())
	_, state, err := c.Initiate(context.Background(), "user")
	if err != nil {
		t.Fatalf("Initiate error: %v", err)
	}
	// Verify state is valid and extractable
	if !IsStateValid(state) {
		t.Error("Initiate produced invalid state")
	}
	if code := ExtractCode(state); len(code) != 4 {
		t.Errorf("expected 4-digit code, got %q", code)
	}
}
