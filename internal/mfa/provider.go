package mfa

import "context"

// ProviderType identifies the type of MFA provider.
type ProviderType string

const (
	ProviderTypeDuo   ProviderType = "duo"
	ProviderTypeEmail ProviderType = "email"
)

// Provider defines the interface for MFA authentication providers.
type Provider interface {
	// Type returns the provider type identifier.
	Type() ProviderType

	// Initiate starts the MFA authentication flow for a user.
	// Returns an authorization URL to redirect the user to, along with
	// a state token that must be verified on callback.
	Initiate(ctx context.Context, username string) (authURL string, state string, err error)

	// Verify validates the MFA callback response.
	Verify(ctx context.Context, code string, state string, username string) error

	// HealthCheck tests connectivity to the MFA provider.
	HealthCheck(ctx context.Context) error
}

// DuoConfig holds non-sensitive MFA provider configuration.
type DuoConfig struct {
	APIHostname string `json:"api_hostname"`
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
}

// DuoSecrets holds sensitive MFA provider configuration.
type DuoSecrets struct {
	ClientSecret string `json:"client_secret"`
}

// EmailOTPConfig holds configuration for the Email OTP provider.
type EmailOTPConfig struct {
	OTPLength     int    `json:"otp_length"`      // number of digits, default 6
	OTPTTLMinutes int    `json:"otp_ttl_minutes"` // code validity window, default 5
	EmailSubject  string `json:"email_subject"`   // subject line for OTP emails
}
