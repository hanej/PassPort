// Package emailotp implements the mfa.Provider interface for email-based OTP authentication.
package emailotp

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/hanej/passport/internal/mfa"
)

// Compile-time check that Client satisfies mfa.Provider.
var _ mfa.Provider = (*Client)(nil)

// Client implements mfa.Provider for email-based OTP authentication.
// The OTP code is generated in Initiate and returned in the state string so
// that the handler can extract it and send it via email. The state is also
// stored server-side in the session; the client code submitted by the user is
// verified against it in Verify.
type Client struct {
	cfg    mfa.EmailOTPConfig
	logger *slog.Logger
}

// New creates a new Email OTP client.
func New(cfg mfa.EmailOTPConfig, logger *slog.Logger) *Client {
	if cfg.OTPLength <= 0 {
		cfg.OTPLength = 6
	}
	if cfg.OTPTTLMinutes <= 0 {
		cfg.OTPTTLMinutes = 5
	}
	if cfg.EmailSubject == "" {
		cfg.EmailSubject = "Your verification code"
	}
	return &Client{cfg: cfg, logger: logger}
}

// Type returns ProviderTypeEmail.
func (c *Client) Type() mfa.ProviderType {
	return mfa.ProviderTypeEmail
}

// Initiate generates a numeric OTP code and returns it encoded in the state
// string. authURL is always empty for email OTP (no external redirect).
// State format: "otp:<code>:<unix_expiry>"
func (c *Client) Initiate(_ context.Context, _ string) (authURL string, state string, err error) {
	code, err := generateOTP(c.cfg.OTPLength)
	if err != nil {
		return "", "", fmt.Errorf("generating OTP: %w", err)
	}

	expiry := time.Now().Add(time.Duration(c.cfg.OTPTTLMinutes) * time.Minute).Unix()
	state = fmt.Sprintf("otp:%s:%d", code, expiry)
	return "", state, nil
}

// Verify validates the submitted code against the state stored in the session.
// state format: "otp:<code>:<unix_expiry>"
func (c *Client) Verify(_ context.Context, code, state, _ string) error {
	parts := strings.SplitN(state, ":", 3)
	if len(parts) != 3 || parts[0] != "otp" {
		return fmt.Errorf("invalid OTP state format")
	}

	storedCode := parts[1]
	expiryUnix, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid OTP expiry in state")
	}

	if time.Now().Unix() > expiryUnix {
		return fmt.Errorf("OTP code has expired")
	}

	if subtle.ConstantTimeCompare([]byte(code), []byte(storedCode)) != 1 {
		return fmt.Errorf("invalid OTP code")
	}

	return nil
}

// HealthCheck always returns nil — email OTP has no external dependency to probe.
// SMTP health is checked via the admin SMTP test endpoint.
func (c *Client) HealthCheck(_ context.Context) error {
	return nil
}

// OTPLength returns the configured OTP digit length.
func (c *Client) OTPLength() int {
	return c.cfg.OTPLength
}

// TTLMinutes returns the configured OTP validity window in minutes.
func (c *Client) TTLMinutes() int {
	return c.cfg.OTPTTLMinutes
}

// EmailSubject returns the configured email subject line.
func (c *Client) EmailSubject() string {
	return c.cfg.EmailSubject
}

// ExtractCode parses the OTP code out of a state string for email sending.
// Returns an empty string if the state is not a valid OTP state.
func ExtractCode(state string) string {
	parts := strings.SplitN(state, ":", 3)
	if len(parts) != 3 || parts[0] != "otp" {
		return ""
	}
	return parts[1]
}

// IsStateValid returns true if state is a well-formed OTP state that has not
// yet expired. Used by ShowMFA to avoid re-generating (and re-sending) a code
// when the user already has a live one (e.g. browser back-navigation).
func IsStateValid(state string) bool {
	parts := strings.SplitN(state, ":", 3)
	if len(parts) != 3 || parts[0] != "otp" {
		return false
	}
	expiryUnix, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Unix() <= expiryUnix
}

// generateOTP generates a cryptographically random numeric OTP of n digits,
// zero-padded to exactly n characters (e.g. n=6, value=42 → "000042").
// n must be ≤ 18 so the value fits in int64.
func generateOTP(n int) (string, error) {
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil)
	num, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", n, num.Int64()), nil
}
