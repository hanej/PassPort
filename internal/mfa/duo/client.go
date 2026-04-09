package duo

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/duosecurity/duo_universal_golang/duouniversal"
	"github.com/hanej/passport/internal/mfa"
)

// Compile-time check that Client satisfies mfa.Provider.
var _ mfa.Provider = (*Client)(nil)

// DuoClient wraps the Duo Universal SDK to satisfy the mfa.Provider interface.
type DuoClient interface {
	HealthCheck() (*duouniversal.HealthCheckResponse, error)
	CreateAuthURL(username string, state string) (string, error)
	GenerateState() (string, error)
	ExchangeAuthorizationCodeFor2faResult(duoCode string, username string) (*duouniversal.TokenResponse, error)
}

// Client implements mfa.Provider for Duo Security Universal Prompt.
type Client struct {
	duo    DuoClient
	logger *slog.Logger
}

// New creates a new Duo MFA client.
func New(cfg mfa.DuoConfig, secrets mfa.DuoSecrets, logger *slog.Logger, opts ...Option) (*Client, error) {
	o := options{}
	for _, opt := range opts {
		opt(&o)
	}

	var (
		duoClient *duouniversal.Client
		err       error
	)
	if o.httpClient != nil {
		duoClient, err = duouniversal.NewClient(
			cfg.ClientID,
			secrets.ClientSecret,
			cfg.APIHostname,
			cfg.RedirectURI,
			duouniversal.WithHTTPClient(o.httpClient),
		)
	} else {
		duoClient, err = duouniversal.NewClient(
			cfg.ClientID,
			secrets.ClientSecret,
			cfg.APIHostname,
			cfg.RedirectURI,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("creating duo client: %w", err)
	}

	return &Client{
		duo:    duoClient,
		logger: logger.With("component", "duo-mfa"),
	}, nil
}

// newFromDuoClient creates a Client from an existing DuoClient (for testing).
func newFromDuoClient(duo DuoClient, logger *slog.Logger) *Client {
	return &Client{
		duo:    duo,
		logger: logger.With("component", "duo-mfa"),
	}
}

// options holds optional configuration for the Duo client.
type options struct {
	httpClient *http.Client
}

// Option configures the Duo client.
type Option func(*options)

// WithHTTPClient sets a custom HTTP client for the Duo SDK.
func WithHTTPClient(c *http.Client) Option {
	return func(o *options) {
		o.httpClient = c
	}
}

// Type returns ProviderTypeDuo.
func (c *Client) Type() mfa.ProviderType { return mfa.ProviderTypeDuo }

// Initiate starts the Duo Universal Prompt authentication flow.
// It generates a cryptographic state token and builds the Duo authorization URL.
func (c *Client) Initiate(_ context.Context, username string) (string, string, error) {
	c.logger.Debug("initiating duo mfa", "username", username)

	state, err := c.duo.GenerateState()
	if err != nil {
		return "", "", fmt.Errorf("generating state: %w", err)
	}

	authURL, err := c.duo.CreateAuthURL(username, state)
	if err != nil {
		return "", "", fmt.Errorf("creating auth url: %w", err)
	}

	c.logger.Debug("duo auth url created", "username", username)
	return authURL, state, nil
}

// Verify validates the Duo callback by exchanging the authorization code
// for a 2FA result and checking that authentication succeeded.
func (c *Client) Verify(_ context.Context, code string, _ string, username string) error {
	c.logger.Debug("verifying duo mfa callback", "username", username)

	resp, err := c.duo.ExchangeAuthorizationCodeFor2faResult(code, username)
	if err != nil {
		return fmt.Errorf("exchanging duo code: %w", err)
	}

	if resp.AuthResult.Result != "allow" {
		c.logger.Warn("duo mfa denied",
			"username", username,
			"result", resp.AuthResult.Result,
			"status", resp.AuthResult.Status,
		)
		return fmt.Errorf("duo authentication denied: %s", resp.AuthResult.Status)
	}

	c.logger.Info("duo mfa verified", "username", username)
	return nil
}

// HealthCheck tests connectivity to the Duo API.
func (c *Client) HealthCheck(_ context.Context) error {
	c.logger.Debug("performing duo health check")

	resp, err := c.duo.HealthCheck()
	if err != nil {
		return fmt.Errorf("duo health check failed: %w", err)
	}

	if resp.Stat != "OK" {
		return fmt.Errorf("duo health check returned status: %s (message: %s)", resp.Stat, resp.Message)
	}

	c.logger.Debug("duo health check passed")
	return nil
}
