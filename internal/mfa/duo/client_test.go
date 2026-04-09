package duo

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"testing"

	"github.com/duosecurity/duo_universal_golang/duouniversal"
	"github.com/hanej/passport/internal/mfa"
)

// mockDuoClient implements the DuoClient interface for testing.
type mockDuoClient struct {
	healthCheckResp   *duouniversal.HealthCheckResponse
	healthCheckErr    error
	generateStateResp string
	generateStateErr  error
	createAuthURLResp string
	createAuthURLErr  error
	exchangeResp      *duouniversal.TokenResponse
	exchangeErr       error
}

func (m *mockDuoClient) HealthCheck() (*duouniversal.HealthCheckResponse, error) {
	return m.healthCheckResp, m.healthCheckErr
}

func (m *mockDuoClient) GenerateState() (string, error) {
	return m.generateStateResp, m.generateStateErr
}

func (m *mockDuoClient) CreateAuthURL(username, state string) (string, error) {
	return m.createAuthURLResp, m.createAuthURLErr
}

func (m *mockDuoClient) ExchangeAuthorizationCodeFor2faResult(duoCode, username string) (*duouniversal.TokenResponse, error) {
	return m.exchangeResp, m.exchangeErr
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestType(t *testing.T) {
	c := newFromDuoClient(&mockDuoClient{}, testLogger())
	if c.Type() != mfa.ProviderTypeDuo {
		t.Errorf("expected ProviderTypeDuo, got %v", c.Type())
	}
}

func TestInitiate_Success(t *testing.T) {
	mock := &mockDuoClient{
		generateStateResp: "state-abc123",
		createAuthURLResp: "https://duo.example.com/auth?state=state-abc123",
	}
	c := newFromDuoClient(mock, testLogger())

	authURL, state, err := c.Initiate(context.Background(), "jdoe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state != "state-abc123" {
		t.Errorf("expected state state-abc123, got %s", state)
	}
	if authURL != "https://duo.example.com/auth?state=state-abc123" {
		t.Errorf("unexpected authURL: %s", authURL)
	}
}

func TestInitiate_GenerateStateError(t *testing.T) {
	mock := &mockDuoClient{
		generateStateErr: errors.New("state generation failed"),
	}
	c := newFromDuoClient(mock, testLogger())

	_, _, err := c.Initiate(context.Background(), "jdoe")
	if err == nil {
		t.Error("expected error from GenerateState failure")
	}
}

func TestInitiate_CreateAuthURLError(t *testing.T) {
	mock := &mockDuoClient{
		generateStateResp: "state-xyz",
		createAuthURLErr:  errors.New("auth URL creation failed"),
	}
	c := newFromDuoClient(mock, testLogger())

	_, _, err := c.Initiate(context.Background(), "jdoe")
	if err == nil {
		t.Error("expected error from CreateAuthURL failure")
	}
}

func TestVerify_Success(t *testing.T) {
	resp := &duouniversal.TokenResponse{}
	resp.AuthResult.Result = "allow"

	mock := &mockDuoClient{exchangeResp: resp}
	c := newFromDuoClient(mock, testLogger())

	if err := c.Verify(context.Background(), "duo-code", "state", "jdoe"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerify_ExchangeError(t *testing.T) {
	mock := &mockDuoClient{
		exchangeErr: errors.New("exchange failed"),
	}
	c := newFromDuoClient(mock, testLogger())

	if err := c.Verify(context.Background(), "duo-code", "state", "jdoe"); err == nil {
		t.Error("expected error from exchange failure")
	}
}

func TestVerify_Denied(t *testing.T) {
	resp := &duouniversal.TokenResponse{}
	resp.AuthResult.Result = "deny"
	resp.AuthResult.Status = "fraud"

	mock := &mockDuoClient{exchangeResp: resp}
	c := newFromDuoClient(mock, testLogger())

	err := c.Verify(context.Background(), "duo-code", "state", "jdoe")
	if err == nil {
		t.Error("expected error for denied authentication")
	}
}

func TestHealthCheck_OK(t *testing.T) {
	resp := &duouniversal.HealthCheckResponse{Stat: "OK"}
	mock := &mockDuoClient{healthCheckResp: resp}
	c := newFromDuoClient(mock, testLogger())

	if err := c.HealthCheck(context.Background()); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHealthCheck_Error(t *testing.T) {
	mock := &mockDuoClient{healthCheckErr: errors.New("API unreachable")}
	c := newFromDuoClient(mock, testLogger())

	if err := c.HealthCheck(context.Background()); err == nil {
		t.Error("expected error from health check failure")
	}
}

func TestHealthCheck_BadStat(t *testing.T) {
	resp := &duouniversal.HealthCheckResponse{
		Stat:    "FAIL",
		Message: "service unavailable",
	}
	mock := &mockDuoClient{healthCheckResp: resp}
	c := newFromDuoClient(mock, testLogger())

	if err := c.HealthCheck(context.Background()); err == nil {
		t.Error("expected error for non-OK stat")
	}
}

func TestNew_ValidConfig(t *testing.T) {
	cfg := mfa.DuoConfig{
		ClientID:    "12345678901234567890", // 20 chars
		APIHostname: "api.duo.example.com",
		RedirectURI: "https://app.example.com/duo/callback",
	}
	secrets := mfa.DuoSecrets{
		ClientSecret: "1234567890123456789012345678901234567890", // 40 chars
	}
	client, err := New(cfg, secrets, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Error("expected non-nil client")
	}
}

func TestNew_InvalidClientID(t *testing.T) {
	cfg := mfa.DuoConfig{
		ClientID:    "tooshort", // invalid
		APIHostname: "api.duo.example.com",
		RedirectURI: "https://app.example.com/duo/callback",
	}
	secrets := mfa.DuoSecrets{
		ClientSecret: "1234567890123456789012345678901234567890",
	}
	_, err := New(cfg, secrets, testLogger())
	if err == nil {
		t.Error("expected error for invalid ClientID")
	}
}

func TestNew_WithHTTPClientOption(t *testing.T) {
	cfg := mfa.DuoConfig{
		ClientID:    "12345678901234567890",
		APIHostname: "api.duo.example.com",
		RedirectURI: "https://app.example.com/duo/callback",
	}
	secrets := mfa.DuoSecrets{
		ClientSecret: "1234567890123456789012345678901234567890",
	}
	// Pass a real http.Client so o.httpClient != nil and exercises the WithHTTPClient branch.
	client, err := New(cfg, secrets, testLogger(), WithHTTPClient(http.DefaultClient))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Error("expected non-nil client")
	}
}

func TestWithHTTPClient_Option(t *testing.T) {
	// Verify WithHTTPClient option is accepted (we can't easily test without a real Duo server,
	// but we validate the option construction doesn't panic).
	opt := WithHTTPClient(nil)
	o := options{}
	opt(&o)
	if o.httpClient != nil {
		t.Error("expected nil http client after setting nil")
	}
}
