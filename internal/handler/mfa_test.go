package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
	"github.com/hanej/passport/internal/mfa"
	"github.com/hanej/passport/internal/mfa/emailotp"
)

func mfaHandlerStubRenderer(t *testing.T) *Renderer {
	t.Helper()
	funcMap := template.FuncMap{
		"add":          func(a, b int) int { return a + b },
		"subtract":     func(a, b int) int { return a - b },
		"pages":        func(n int) []int { return nil },
		"markdownHTML": func(s string) template.HTML { return template.HTML(s) },
		"contains":     strings.Contains,
		"hexToRGB":     func(s string) string { return "" },
		"darkenHex":    func(s string, f float64) string { return s },
		"branding":     func() *db.BrandingConfig { return &db.BrandingConfig{} },
	}
	pages := make(map[string]*template.Template)
	pages["mfa_otp.html"] = template.Must(
		template.New("mfa_otp.html").Funcs(funcMap).Parse(`{{define "base"}}mfa otp {{if .Flash}}{{.Flash.message}}{{end}}{{end}}`))
	pages["error.html"] = template.Must(
		template.New("error.html").Funcs(funcMap).Parse(`{{define "base"}}error{{end}}`))

	return &Renderer{pages: pages, logger: testLogger()}
}

type mfaHandlerTestEnv struct {
	db       *db.DB
	sm       *auth.SessionManager
	handler  *MFAHandler
	registry *idp.Registry
	crypto   *crypto.Service
}

func setupMFAHandlerTest(t *testing.T) *mfaHandlerTestEnv {
	t.Helper()

	database := setupTestDB(t)
	logger := testLogger()

	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := mfaHandlerStubRenderer(t)
	registry := idp.NewRegistry(logger)

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	cryptoSvc, err := crypto.NewService(key, 1)
	if err != nil {
		t.Fatalf("creating crypto service: %v", err)
	}

	tmpFile, err := os.CreateTemp(t.TempDir(), "audit-*.log")
	if err != nil {
		t.Fatalf("creating audit file: %v", err)
	}
	_ = tmpFile.Close()

	auditLog, err := audit.NewLogger(database, tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("creating audit logger: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })

	h := NewMFAHandler(database, sm, cryptoSvc, registry, renderer, auditLog, logger)

	return &mfaHandlerTestEnv{
		db:       database,
		sm:       sm,
		handler:  h,
		registry: registry,
		crypto:   cryptoSvc,
	}
}

func (env *mfaHandlerTestEnv) createSession(t *testing.T, userType, providerID, username string) []*http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := env.sm.CreateSession(w, r, userType, providerID, username, false, false)
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}
	return w.Result().Cookies()
}

func (env *mfaHandlerTestEnv) serveWithSession(t *testing.T, handler http.HandlerFunc, method, path string, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	wrapped := env.sm.Middleware(handler)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	return rec
}

// ---- buildOTPEmailBody ----

func TestBuildOTPEmailBody(t *testing.T) {
	body := buildOTPEmailBody("123456", 10)
	if !strings.Contains(body, "123456") {
		t.Errorf("expected OTP code in body, got: %s", body)
	}
	if !strings.Contains(body, "10") {
		t.Errorf("expected TTL in body, got: %s", body)
	}
}

// ---- postMFARedirect ----

func TestPostMFARedirect_Reset(t *testing.T) {
	env := setupMFAHandlerTest(t)
	sess := &db.Session{UserType: "reset"}
	got := env.handler.postMFARedirect(sess)
	if got != "/reset-password" {
		t.Errorf("expected /reset-password, got %s", got)
	}
}

func TestPostMFARedirect_Dashboard(t *testing.T) {
	env := setupMFAHandlerTest(t)
	sess := &db.Session{UserType: "provider"}
	got := env.handler.postMFARedirect(sess)
	if got != "/dashboard" {
		t.Errorf("expected /dashboard, got %s", got)
	}
}

// ---- ShowMFA ----

func TestShowMFA_NoSession(t *testing.T) {
	env := setupMFAHandlerTest(t)
	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	rec := httptest.NewRecorder()
	env.handler.ShowMFA(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected /login redirect, got %s", loc)
	}
}

func TestShowMFA_NoMFAProvider_Redirects(t *testing.T) {
	// No MFA provider configured → client == nil → redirect to postMFARedirect.
	env := setupMFAHandlerTest(t)
	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")

	rec := env.serveWithSession(t, env.handler.ShowMFA, http.MethodGet, "/mfa", cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected /dashboard, got %s", loc)
	}
}

func TestShowMFA_ResetSession_NoMFA_Redirects(t *testing.T) {
	env := setupMFAHandlerTest(t)
	cookies := env.createSession(t, "reset", "corp-ad", "jdoe")

	rec := env.serveWithSession(t, env.handler.ShowMFA, http.MethodGet, "/mfa", cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/reset-password" {
		t.Errorf("expected /reset-password, got %s", loc)
	}
}

// ---- Callback ----

func TestCallback_NoSession(t *testing.T) {
	env := setupMFAHandlerTest(t)
	req := httptest.NewRequest(http.MethodGet, "/mfa/callback", nil)
	rec := httptest.NewRecorder()
	env.handler.Callback(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected /login, got %s", loc)
	}
}

func TestCallback_MissingParams(t *testing.T) {
	env := setupMFAHandlerTest(t)
	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")

	// No duo_code or state in query.
	rec := env.serveWithSession(t, env.handler.Callback, http.MethodGet, "/mfa/callback", cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
}

func TestCallback_StateMismatch(t *testing.T) {
	env := setupMFAHandlerTest(t)
	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")

	// Session MFAState is "" but we pass state="different-state".
	rec := env.serveWithSession(t, env.handler.Callback, http.MethodGet, "/mfa/callback?duo_code=abc&state=wrong-state", cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
}

// ---- VerifyOTP ----

func TestVerifyOTP_NoSession(t *testing.T) {
	env := setupMFAHandlerTest(t)
	req := httptest.NewRequest(http.MethodPost, "/mfa/verify-otp", nil)
	rec := httptest.NewRecorder()
	env.handler.VerifyOTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected /login, got %s", loc)
	}
}

func TestVerifyOTP_NoMFAProvider(t *testing.T) {
	env := setupMFAHandlerTest(t)
	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")

	// No MFA configured → client == nil → error redirect.
	rec := env.serveWithSession(t, env.handler.VerifyOTP, http.MethodPost, "/mfa/verify-otp", cookies, "code=123456")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
}

// ---- ResendOTP ----

func TestResendOTP_NoSession(t *testing.T) {
	env := setupMFAHandlerTest(t)
	req := httptest.NewRequest(http.MethodPost, "/mfa/resend-otp", nil)
	rec := httptest.NewRecorder()
	env.handler.ResendOTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected /login, got %s", loc)
	}
}

func TestResendOTP_NoMFAProvider(t *testing.T) {
	env := setupMFAHandlerTest(t)
	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")

	// No MFA configured → error redirect.
	rec := env.serveWithSession(t, env.handler.ResendOTP, http.MethodPost, "/mfa/resend-otp", cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
}

// ---- buildEmailConfigFromRecord ----

func TestBuildEmailConfigFromRecord_Success(t *testing.T) {
	key, _ := crypto.GenerateKey()
	cryptoSvc, _ := crypto.NewService(key, 1)

	cfg := map[string]any{
		"host":            "smtp.example.com",
		"port":            "587",
		"from_address":    "no-reply@example.com",
		"from_name":       "PassPort",
		"use_tls":         false,
		"use_starttls":    true,
		"tls_skip_verify": false,
		"enabled":         true,
	}
	cfgJSON, _ := json.Marshal(cfg)

	rec := &db.SMTPConfig{
		ConfigJSON: string(cfgJSON),
	}

	emailCfg, err := buildEmailConfigFromRecord(rec, cryptoSvc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if emailCfg.Host != "smtp.example.com" {
		t.Errorf("expected host smtp.example.com, got %s", emailCfg.Host)
	}
	if emailCfg.Port != "587" {
		t.Errorf("expected port 587, got %s", emailCfg.Port)
	}
	if !emailCfg.UseStartTLS {
		t.Error("expected UseStartTLS to be true")
	}
}

func TestBuildEmailConfigFromRecord_Disabled(t *testing.T) {
	key, _ := crypto.GenerateKey()
	cryptoSvc, _ := crypto.NewService(key, 1)

	cfg := map[string]any{
		"host":    "smtp.example.com",
		"port":    "25",
		"enabled": false,
	}
	cfgJSON, _ := json.Marshal(cfg)

	rec := &db.SMTPConfig{ConfigJSON: string(cfgJSON)}
	_, err := buildEmailConfigFromRecord(rec, cryptoSvc)
	if err == nil {
		t.Error("expected error for disabled SMTP, got nil")
	}
}

func TestBuildEmailConfigFromRecord_InvalidJSON(t *testing.T) {
	key, _ := crypto.GenerateKey()
	cryptoSvc, _ := crypto.NewService(key, 1)

	rec := &db.SMTPConfig{ConfigJSON: "not-json}"}
	_, err := buildEmailConfigFromRecord(rec, cryptoSvc)
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestBuildEmailConfigFromRecord_WithSecrets(t *testing.T) {
	key, _ := crypto.GenerateKey()
	cryptoSvc, _ := crypto.NewService(key, 1)

	cfg := map[string]any{
		"host":    "smtp.example.com",
		"port":    "587",
		"enabled": true,
	}
	cfgJSON, _ := json.Marshal(cfg)

	secrets := map[string]string{
		"username": "smtpuser",
		"password": "smtppass",
	}
	secretsJSON, _ := json.Marshal(secrets)
	encrypted, err := cryptoSvc.Encrypt(secretsJSON)
	if err != nil {
		t.Fatalf("encrypting secrets: %v", err)
	}

	rec := &db.SMTPConfig{
		ConfigJSON: string(cfgJSON),
		SecretBlob: encrypted,
	}

	emailCfg, err := buildEmailConfigFromRecord(rec, cryptoSvc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if emailCfg.Username != "smtpuser" {
		t.Errorf("expected username smtpuser, got %s", emailCfg.Username)
	}
	if emailCfg.Password != "smtppass" {
		t.Errorf("expected password smtppass, got %s", emailCfg.Password)
	}
}

// ---- idp.Registry ----

func TestMFAHandlerRegistryNotFound(t *testing.T) {
	env := setupMFAHandlerTest(t)

	// resolveUserEmail: IDP not in registry.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := env.handler.resolveUserEmail(req, "nonexistent-idp", "jdoe")
	if err == nil {
		t.Error("expected error when IDP not in registry")
	}
}

// ---- renderOTPForm ----

func TestRenderOTPForm_WithFlash(t *testing.T) {
	env := setupMFAHandlerTest(t)
	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	rec := httptest.NewRecorder()
	env.handler.renderOTPForm(rec, req, 10, "Invalid code")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Invalid code") {
		t.Errorf("expected error message in response, got: %s", rec.Body.String())
	}
}

func TestRenderOTPForm_NoFlash(t *testing.T) {
	env := setupMFAHandlerTest(t)
	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	rec := httptest.NewRecorder()
	env.handler.renderOTPForm(rec, req, 5, "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// ---- completeMFA ----

func TestCompleteMFA_ResetSession(t *testing.T) {
	env := setupMFAHandlerTest(t)
	cookies := env.createSession(t, "reset", "corp-ad", "jdoe")

	var redirectLoc string
	checkHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := auth.SessionFromContext(r.Context())
		env.handler.completeMFA(w, r, sess)
		redirectLoc = w.Header().Get("Location")
	})

	env.serveWithSession(t, checkHandler, http.MethodPost, "/mfa/verify-otp", cookies, "")

	if redirectLoc != "/reset-password" {
		t.Errorf("expected /reset-password, got %s", redirectLoc)
	}
}

func TestCompleteMFA_DashboardSession(t *testing.T) {
	env := setupMFAHandlerTest(t)
	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")

	var redirectLoc string
	checkHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := auth.SessionFromContext(r.Context())
		env.handler.completeMFA(w, r, sess)
		redirectLoc = w.Header().Get("Location")
	})

	env.serveWithSession(t, checkHandler, http.MethodPost, "/mfa/verify-otp", cookies, "")

	if redirectLoc != "/dashboard" {
		t.Errorf("expected /dashboard, got %s", redirectLoc)
	}
}

// ---- sendOTPEmail ----

func TestSendOTPEmail_NoSMTP(t *testing.T) {
	env := setupMFAHandlerTest(t)

	otpClient := emailotp.New(mfa.EmailOTPConfig{OTPLength: 6, OTPTTLMinutes: 5}, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	err := env.handler.sendOTPEmail(req, otpClient, "user@example.com", "123456")
	if err == nil {
		t.Error("expected error when SMTP not configured")
	}
}

// ---- buildMFAClient ----

func TestBuildMFAClient_EmailOTP(t *testing.T) {
	env := setupMFAHandlerTest(t)

	// Create email OTP provider and set as global default.
	cfgBytes, _ := json.Marshal(mfa.EmailOTPConfig{OTPLength: 6, OTPTTLMinutes: 5})
	record := &db.MFAProviderRecord{
		ID:           "email-otp-1",
		Name:         "email-otp",
		ProviderType: "email",
		Enabled:      true,
		ConfigJSON:   string(cfgBytes),
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}
	id := "email-otp-1"
	if err := env.db.SetDefaultMFAProviderID(context.Background(), &id); err != nil {
		t.Fatalf("setting default MFA provider: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	client, pRecord, err := env.handler.buildMFAClient(req, "some-idp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Error("expected non-nil client")
	}
	if pRecord == nil {
		t.Error("expected non-nil provider record")
	}
	if _, ok := client.(*emailotp.Client); !ok {
		t.Error("expected *emailotp.Client")
	}
}

func TestBuildMFAClient_NoProvider(t *testing.T) {
	// When no MFA provider is configured, buildMFAClient returns nil, nil, nil.
	env := setupMFAHandlerTest(t)

	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	client, record, err := env.handler.buildMFAClient(req, "some-idp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client != nil || record != nil {
		t.Error("expected nil client and record when no MFA configured")
	}
}

// ---- resolveUserEmail ----

func TestResolveUserEmail_Success(t *testing.T) {
	env := setupMFAHandlerTest(t)

	// Register a mock provider that returns a userDN.
	env.registry.Register("corp-idp", &mockProvider{id: "corp-idp"})

	// Create an IDP record in the DB.
	idpCfg := idp.Config{}
	cfgBytes, _ := json.Marshal(idpCfg)
	if err := env.db.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-idp",
		FriendlyName: "Corp IDP",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(cfgBytes),
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	// mockProvider.SearchUser returns ("", nil) and GetUserAttribute returns ("", nil).
	email, err := env.handler.resolveUserEmail(req, "corp-idp", "jdoe")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Empty string email is OK — mockProvider returns "".
	_ = email
}

func TestResolveUserEmail_IDPNotInDB(t *testing.T) {
	env := setupMFAHandlerTest(t)

	env.registry.Register("corp-idp", &mockProvider{id: "corp-idp"})

	// No IDP record in DB → GetIDP should fail.
	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	_, err := env.handler.resolveUserEmail(req, "corp-idp", "jdoe")
	if err == nil {
		t.Error("expected error when IDP not in DB")
	}
}

// ---- VerifyOTP with email OTP configured ----

func TestVerifyOTP_InvalidCode(t *testing.T) {
	env := setupMFAHandlerTest(t)

	// Set up email OTP as global default.
	cfgBytes, _ := json.Marshal(mfa.EmailOTPConfig{OTPLength: 6, OTPTTLMinutes: 5})
	record := &db.MFAProviderRecord{
		ID:           "email-otp-verify",
		Name:         "email-otp",
		ProviderType: "email",
		Enabled:      true,
		ConfigJSON:   string(cfgBytes),
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}
	mfaID := "email-otp-verify"
	if err := env.db.SetDefaultMFAProviderID(context.Background(), &mfaID); err != nil {
		t.Fatalf("setting default: %v", err)
	}

	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")

	// Send wrong code → VerifyOTP renders the OTP form with an error message.
	rec := env.serveWithSession(t, env.handler.VerifyOTP, http.MethodPost, "/mfa/verify-otp", cookies, "code=000000")

	// Should render OTP form (200) or redirect.
	if rec.Code != http.StatusOK && rec.Code != http.StatusFound {
		t.Errorf("unexpected status %d", rec.Code)
	}
}

// ---- ResendOTP with reset session ----

func TestResendOTP_ResetSession_ErrorRedirect(t *testing.T) {
	env := setupMFAHandlerTest(t)

	// Set up email OTP as global default.
	cfgBytes, _ := json.Marshal(mfa.EmailOTPConfig{OTPLength: 6, OTPTTLMinutes: 5})
	record := &db.MFAProviderRecord{
		ID:           "email-otp-resend",
		Name:         "email-otp",
		ProviderType: "email",
		Enabled:      true,
		ConfigJSON:   string(cfgBytes),
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}
	mfaID := "email-otp-resend"
	if err := env.db.SetDefaultMFAProviderID(context.Background(), &mfaID); err != nil {
		t.Fatalf("setting default: %v", err)
	}

	// Reset session — on failure should redirect to /forgot-password.
	cookies := env.createSession(t, "reset", "corp-ad", "jdoe")
	rec := env.serveWithSession(t, env.handler.ResendOTP, http.MethodPost, "/mfa/resend-otp", cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	// Should redirect to /forgot-password (not /dashboard) because userType == "reset".
	loc := rec.Header().Get("Location")
	if loc != "/forgot-password" {
		t.Errorf("expected /forgot-password, got %s", loc)
	}
}

// ---- ShowMFA with reset session ----

func TestShowMFA_ResetSession_InvalidEmailAttr_Redirects(t *testing.T) {
	// Reset session with no MFA provider configured → should redirect to /reset-password.
	env := setupMFAHandlerTest(t)
	cookies := env.createSession(t, "reset", "corp-ad", "jdoe")

	rec := env.serveWithSession(t, env.handler.ShowMFA, http.MethodGet, "/mfa", cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
}

func TestShowMFA_BrandingSetInRenderer(t *testing.T) {
	// Ensure SetBranding is set to non-nil on a new renderer (covers branding init path).
	logger := testLogger()
	r, err := NewRenderer("", logger)
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}
	if r.branding.Load() == nil {
		t.Error("expected branding to be initialized")
	}
}

// ---- ShowMFA with email OTP configured ----

func TestShowMFA_EmailOTP_NoUserEmail(t *testing.T) {
	// Email OTP configured but IDP not in registry → resolveUserEmail fails → redirect.
	env := setupMFAHandlerTest(t)

	cfgBytes, _ := json.Marshal(mfa.EmailOTPConfig{OTPLength: 6, OTPTTLMinutes: 5})
	record := &db.MFAProviderRecord{
		ID:           "email-otp-show",
		Name:         "email-otp",
		ProviderType: "email",
		Enabled:      true,
		ConfigJSON:   string(cfgBytes),
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}
	mfaID := "email-otp-show"
	if err := env.db.SetDefaultMFAProviderID(context.Background(), &mfaID); err != nil {
		t.Fatalf("setting default MFA provider: %v", err)
	}

	// Session with providerID "corp-ad" not in registry → resolveUserEmail fails.
	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")
	rec := env.serveWithSession(t, env.handler.ShowMFA, http.MethodGet, "/mfa", cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if loc != "/dashboard" {
		t.Errorf("expected /dashboard redirect, got %s", loc)
	}
}

func TestShowMFA_EmailOTP_ResetNoUserEmail(t *testing.T) {
	// Email OTP configured, reset session, IDP not in registry → redirect to /forgot-password.
	env := setupMFAHandlerTest(t)

	cfgBytes, _ := json.Marshal(mfa.EmailOTPConfig{OTPLength: 6, OTPTTLMinutes: 5})
	record := &db.MFAProviderRecord{
		ID:           "email-otp-show-reset",
		Name:         "email-otp",
		ProviderType: "email",
		Enabled:      true,
		ConfigJSON:   string(cfgBytes),
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}
	mfaID := "email-otp-show-reset"
	if err := env.db.SetDefaultMFAProviderID(context.Background(), &mfaID); err != nil {
		t.Fatalf("setting default MFA provider: %v", err)
	}

	cookies := env.createSession(t, "reset", "corp-ad", "jdoe")
	rec := env.serveWithSession(t, env.handler.ShowMFA, http.MethodGet, "/mfa", cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "/forgot-password" {
		t.Errorf("expected /forgot-password, got %s", loc)
	}
}

// ============================================================
// Additional mock types for coverage of error paths.
// ============================================================

// mockUpdateSessionMFAErrStore wraps *db.DB and makes UpdateSessionMFA return an error.
type mockUpdateSessionMFAErrStore struct {
	*db.DB
	err error
}

func (m *mockUpdateSessionMFAErrStore) UpdateSessionMFA(ctx context.Context, id string, mfaPending bool, mfaState string) error {
	if m.err != nil {
		return m.err
	}
	return m.DB.UpdateSessionMFA(ctx, id, mfaPending, mfaState)
}

// mockMFAGetProviderStore overrides GetMFAProviderForIDP to return an injected record.
type mockMFAGetProviderStore struct {
	*db.DB
	record *db.MFAProviderRecord
	err    error
}

func (m *mockMFAGetProviderStore) GetMFAProviderForIDP(ctx context.Context, idpID string) (*db.MFAProviderRecord, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.record, nil
}

// mockSearchFailProvider overrides SearchUser to always return an error.
type mockSearchFailProvider struct {
	*mockProvider
	searchErr error
}

func (m *mockSearchFailProvider) SearchUser(_ context.Context, _, _ string) (string, error) {
	return "", m.searchErr
}

// mockGetAttrFailProvider overrides GetUserAttribute to always return an error.
type mockGetAttrFailProvider struct {
	*mockProvider
	attrErr error
}

func (m *mockGetAttrFailProvider) GetUserAttribute(_ context.Context, _, _ string) (string, error) {
	return "", m.attrErr
}

// ============================================================
// Additional helpers on mfaHandlerTestEnv.
// ============================================================

// createMFAPendingSession creates a session with MFAPending=true.
func (env *mfaHandlerTestEnv) createMFAPendingSession(t *testing.T, userType, providerID, username string) []*http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	sessID, err := env.sm.CreateSession(w, r, userType, providerID, username, false, false)
	if err != nil {
		t.Fatalf("creating mfaPending session: %v", err)
	}
	if err := env.db.UpdateSessionMFA(context.Background(), sessID, true, ""); err != nil {
		t.Fatalf("setting MFA pending on session: %v", err)
	}
	return w.Result().Cookies()
}

// getSessionID retrieves the session ID from cookies by loading the session via middleware.
func (env *mfaHandlerTestEnv) getSessionID(t *testing.T, cookies []*http.Cookie) string {
	t.Helper()
	var sessID string
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	wrapped := env.sm.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := auth.SessionFromContext(r.Context())
		if sess != nil {
			sessID = sess.ID
		}
	}))
	wrapped.ServeHTTP(rec, req)
	return sessID
}

// newHandlerWithStore creates a fresh MFAHandler using the given store but sharing the rest of env.
func (env *mfaHandlerTestEnv) newHandlerWithStore(t *testing.T, store db.Store) *MFAHandler {
	t.Helper()
	tmpFile, err := os.CreateTemp(t.TempDir(), "audit-*.log")
	if err != nil {
		t.Fatalf("creating audit file: %v", err)
	}
	_ = tmpFile.Close()
	auditLog, err := audit.NewLogger(env.db, tmpFile.Name(), testLogger())
	if err != nil {
		t.Fatalf("creating audit logger: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })
	return NewMFAHandler(store, env.sm, env.crypto, env.registry, mfaHandlerStubRenderer(t), auditLog, testLogger())
}

// setupEmailOTPProvider creates an email OTP MFA provider with the given ID and sets it as default.
func (env *mfaHandlerTestEnv) setupEmailOTPProvider(t *testing.T, id string) {
	t.Helper()
	cfgBytes, _ := json.Marshal(mfa.EmailOTPConfig{OTPLength: 6, OTPTTLMinutes: 5})
	record := &db.MFAProviderRecord{
		ID:           id,
		Name:         "email-otp",
		ProviderType: "email",
		Enabled:      true,
		ConfigJSON:   string(cfgBytes),
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating email OTP provider %q: %v", id, err)
	}
	if err := env.db.SetDefaultMFAProviderID(context.Background(), &id); err != nil {
		t.Fatalf("setting default MFA provider: %v", err)
	}
}

// setupDuoProvider creates a Duo MFA provider with valid config and sets it as default.
func (env *mfaHandlerTestEnv) setupDuoProvider(t *testing.T, id string) {
	t.Helper()
	duoCfg := mfa.DuoConfig{
		ClientID:    "12345678901234567890",
		APIHostname: "api.duo.example.com",
		RedirectURI: "https://app.example.com/duo/callback",
	}
	duoSecrets := mfa.DuoSecrets{
		ClientSecret: "1234567890123456789012345678901234567890",
	}
	cfgBytes, _ := json.Marshal(duoCfg)
	secretsBytes, _ := json.Marshal(duoSecrets)
	encrypted, err := env.crypto.Encrypt(secretsBytes)
	if err != nil {
		t.Fatalf("encrypting Duo secrets: %v", err)
	}
	record := &db.MFAProviderRecord{
		ID:           id,
		Name:         "duo",
		ProviderType: "duo",
		Enabled:      true,
		ConfigJSON:   string(cfgBytes),
		SecretBlob:   encrypted,
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating Duo provider %q: %v", id, err)
	}
	if err := env.db.SetDefaultMFAProviderID(context.Background(), &id); err != nil {
		t.Fatalf("setting default Duo provider: %v", err)
	}
}

// setupIDPWithMockProvider creates an IDP record in the DB and registers the given provider in the registry.
func (env *mfaHandlerTestEnv) setupIDPWithMockProvider(t *testing.T, idpID string, provider idp.Provider) {
	t.Helper()
	cfgBytes, _ := json.Marshal(idp.Config{})
	if err := env.db.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           idpID,
		FriendlyName: "Test IDP",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(cfgBytes),
	}); err != nil {
		t.Fatalf("creating IDP %q: %v", idpID, err)
	}
	env.registry.Register(idpID, provider)
}

// ============================================================
// sendOTPEmail — additional coverage (33.3% → higher)
// ============================================================

func TestSendOTPEmail_DisabledSMTP(t *testing.T) {
	// SMTP configured but disabled → buildEmailConfigFromRecord fails.
	env := setupMFAHandlerTest(t)

	cfg := map[string]any{"host": "smtp.example.com", "port": "587", "enabled": false}
	cfgJSON, _ := json.Marshal(cfg)
	if err := env.db.SaveSMTPConfig(context.Background(), &db.SMTPConfig{ConfigJSON: string(cfgJSON)}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	otpClient := emailotp.New(mfa.EmailOTPConfig{OTPLength: 6, OTPTTLMinutes: 5}, testLogger())
	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	err := env.handler.sendOTPEmail(req, otpClient, "user@example.com", "123456")
	if err == nil {
		t.Error("expected error when SMTP is disabled")
	}
}

func TestSendOTPEmail_SMTPConnectionFails(t *testing.T) {
	// SMTP configured and enabled but unreachable → email.SendHTML fails.
	env := setupMFAHandlerTest(t)

	cfg := map[string]any{
		"host":         "127.0.0.1",
		"port":         "60996",
		"from_address": "from@example.com",
		"enabled":      true,
	}
	cfgJSON, _ := json.Marshal(cfg)
	if err := env.db.SaveSMTPConfig(context.Background(), &db.SMTPConfig{ConfigJSON: string(cfgJSON)}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	otpClient := emailotp.New(mfa.EmailOTPConfig{OTPLength: 6, OTPTTLMinutes: 5}, testLogger())
	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	err := env.handler.sendOTPEmail(req, otpClient, "user@example.com", "123456")
	if err == nil {
		t.Error("expected error when SMTP connection fails")
	}
}

func TestSendOTPEmail_Success(t *testing.T) {
	// SMTP configured pointing to fake server → success.
	env := setupMFAHandlerTest(t)

	addr, stop := fakeSMTPServerHandler(t)
	defer stop()

	host, port, _ := net.SplitHostPort(addr)
	cfg := map[string]any{
		"host":         host,
		"port":         port,
		"from_address": "from@example.com",
		"enabled":      true,
	}
	cfgJSON, _ := json.Marshal(cfg)
	if err := env.db.SaveSMTPConfig(context.Background(), &db.SMTPConfig{ConfigJSON: string(cfgJSON)}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	otpClient := emailotp.New(mfa.EmailOTPConfig{OTPLength: 6, OTPTTLMinutes: 5}, testLogger())
	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	err := env.handler.sendOTPEmail(req, otpClient, "user@example.com", "123456")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// ============================================================
// buildEmailConfigFromRecord — invalid secrets JSON path.
// ============================================================

func TestBuildEmailConfigFromRecord_InvalidSecretsJSON(t *testing.T) {
	key, _ := crypto.GenerateKey()
	cryptoSvc, _ := crypto.NewService(key, 1)

	cfg := map[string]any{"host": "smtp.example.com", "port": "587", "enabled": true}
	cfgJSON, _ := json.Marshal(cfg)

	// Encrypt bytes that are not valid JSON so that json.Unmarshal fails after decrypt.
	encrypted, err := cryptoSvc.Encrypt([]byte("not valid json {"))
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	rec := &db.SMTPConfig{
		ConfigJSON: string(cfgJSON),
		SecretBlob: encrypted,
	}
	_, err = buildEmailConfigFromRecord(rec, cryptoSvc)
	if err == nil {
		t.Error("expected error for invalid secrets JSON, got nil")
	}
}

// ============================================================
// buildMFAClientForIDP — unsupported type + Duo invalid secrets JSON.
// ============================================================

func TestBuildMFAClient_UnsupportedType(t *testing.T) {
	env := setupMFAHandlerTest(t)

	// Use a mock store so we bypass the DB CHECK constraint on provider_type.
	mockStore := &mockMFAGetProviderStore{
		DB: env.db,
		record: &db.MFAProviderRecord{
			ID:           "unknown-type-mfa",
			Name:         "unknown",
			ProviderType: "ldap-auth", // neither "duo" nor "email"
			Enabled:      true,
			ConfigJSON:   "{}",
		},
	}
	h := env.newHandlerWithStore(t, mockStore)

	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	_, _, err := h.buildMFAClient(req, "some-idp")
	if err == nil {
		t.Error("expected error for unsupported MFA provider type, got nil")
	}
}

func TestBuildMFAClient_DuoInvalidSecretsJSON(t *testing.T) {
	// Decrypt succeeds but json.Unmarshal into DuoSecrets fails.
	env := setupMFAHandlerTest(t)

	duoCfg := mfa.DuoConfig{
		ClientID:    "12345678901234567890",
		APIHostname: "api.duo.example.com",
		RedirectURI: "https://app.example.com/duo/callback",
	}
	cfgBytes, _ := json.Marshal(duoCfg)

	// Encrypt non-JSON bytes.
	encrypted, err := env.crypto.Encrypt([]byte("{invalid json"))
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	record := &db.MFAProviderRecord{
		ID:           "duo-bad-secrets-json-2",
		Name:         "duo",
		ProviderType: "duo",
		Enabled:      true,
		ConfigJSON:   string(cfgBytes),
		SecretBlob:   encrypted,
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}
	provID := "duo-bad-secrets-json-2"
	if err := env.db.SetDefaultMFAProviderID(context.Background(), &provID); err != nil {
		t.Fatalf("setting default: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	_, _, err = env.handler.buildMFAClient(req, "some-idp")
	if err == nil {
		t.Error("expected error for invalid Duo secrets JSON, got nil")
	}
}

// ============================================================
// resolveUserEmail — SearchUser fails, GetUserAttribute fails.
// ============================================================

func TestResolveUserEmail_SearchFails(t *testing.T) {
	env := setupMFAHandlerTest(t)

	provider := &mockSearchFailProvider{
		mockProvider: &mockProvider{id: "corp-search-fail"},
		searchErr:    errors.New("LDAP unavailable"),
	}
	env.registry.Register("corp-search-fail", provider)

	cfgBytes, _ := json.Marshal(idp.Config{})
	if err := env.db.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-search-fail",
		FriendlyName: "Corp IDP",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(cfgBytes),
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	_, err := env.handler.resolveUserEmail(req, "corp-search-fail", "jdoe")
	if err == nil {
		t.Error("expected error when SearchUser fails for both uid and sAMAccountName")
	}
}

func TestResolveUserEmail_GetUserAttributeFails(t *testing.T) {
	env := setupMFAHandlerTest(t)

	// SearchUser returns "" (no error) but GetUserAttribute fails.
	provider := &mockGetAttrFailProvider{
		mockProvider: &mockProvider{id: "corp-attr-fail"},
		attrErr:      errors.New("attribute not readable"),
	}
	env.registry.Register("corp-attr-fail", provider)

	cfgBytes, _ := json.Marshal(idp.Config{})
	if err := env.db.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-attr-fail",
		FriendlyName: "Corp IDP",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(cfgBytes),
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	_, err := env.handler.resolveUserEmail(req, "corp-attr-fail", "jdoe")
	if err == nil {
		t.Error("expected error when GetUserAttribute fails")
	}
}

// ============================================================
// ShowMFA — MFAPending paths + UpdateSessionMFA error + email OTP success.
// ============================================================

func TestShowMFA_BuildClientError_NotPending(t *testing.T) {
	// buildMFAClient returns error, session NOT pending → SetFlash + redirect to errorRedirect.
	env := setupMFAHandlerTest(t)

	record := &db.MFAProviderRecord{
		ID:           "bad-mfa-not-pending",
		Name:         "bad",
		ProviderType: "duo",
		Enabled:      true,
		ConfigJSON:   "not-valid-json}",
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}
	id := "bad-mfa-not-pending"
	if err := env.db.SetDefaultMFAProviderID(context.Background(), &id); err != nil {
		t.Fatalf("setting default: %v", err)
	}

	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")
	rec := env.serveWithSession(t, env.handler.ShowMFA, http.MethodGet, "/mfa", cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	// Not pending → errorRedirect = /dashboard.
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected /dashboard, got %s", loc)
	}
}

func TestShowMFA_MFAPending_BuildClientError(t *testing.T) {
	// buildMFAClient returns error, session IS pending → fail open to postMFARedirect.
	env := setupMFAHandlerTest(t)

	record := &db.MFAProviderRecord{
		ID:           "bad-mfa-pending",
		Name:         "bad",
		ProviderType: "duo",
		Enabled:      true,
		ConfigJSON:   "not-valid-json}",
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}
	id := "bad-mfa-pending"
	if err := env.db.SetDefaultMFAProviderID(context.Background(), &id); err != nil {
		t.Fatalf("setting default: %v", err)
	}

	cookies := env.createMFAPendingSession(t, "provider", "corp-ad", "jdoe")
	rec := env.serveWithSession(t, env.handler.ShowMFA, http.MethodGet, "/mfa", cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	// MFAPending=true + error → fail open → /dashboard (UserType="provider").
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected /dashboard for fail open, got %s", loc)
	}
}

func TestShowMFA_MFAPending_NoClient(t *testing.T) {
	// No MFA configured, session IS pending → clear MFA state + redirect to postMFARedirect.
	env := setupMFAHandlerTest(t)

	cookies := env.createMFAPendingSession(t, "provider", "corp-ad", "jdoe")
	rec := env.serveWithSession(t, env.handler.ShowMFA, http.MethodGet, "/mfa", cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	// client==nil + MFAPending → UpdateSessionMFA(clear) + redirect.
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected /dashboard, got %s", loc)
	}
}

func TestShowMFA_UpdateSessionMFAError(t *testing.T) {
	// Email OTP initiated successfully, but UpdateSessionMFA fails → flash + redirect.
	env := setupMFAHandlerTest(t)
	env.setupEmailOTPProvider(t, "otp-show-updsess")

	mockStore := &mockUpdateSessionMFAErrStore{DB: env.db, err: fmt.Errorf("db error")}
	h := env.newHandlerWithStore(t, mockStore)

	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")
	rec := env.serveWithSession(t, h.ShowMFA, http.MethodGet, "/mfa", cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected /dashboard, got %s", loc)
	}
}

func TestShowMFA_EmailOTP_SendFails(t *testing.T) {
	// Email OTP + IDP in registry/DB, UpdateSessionMFA succeeds, resolveUserEmail succeeds,
	// but no SMTP configured → sendOTPEmail fails → redirect.
	env := setupMFAHandlerTest(t)
	env.setupEmailOTPProvider(t, "otp-show-sendfail")
	env.setupIDPWithMockProvider(t, "test-idp-show-sendfail", &mockProvider{id: "test-idp-show-sendfail"})

	// No SMTP saved → sendOTPEmail returns "SMTP not configured".
	cookies := env.createSession(t, "provider", "test-idp-show-sendfail", "jdoe")
	rec := env.serveWithSession(t, env.handler.ShowMFA, http.MethodGet, "/mfa", cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected /dashboard, got %s", loc)
	}
}

func TestShowMFA_EmailOTP_Success(t *testing.T) {
	// Email OTP + IDP in registry/DB + working SMTP → renders OTP form (200).
	env := setupMFAHandlerTest(t)
	env.setupEmailOTPProvider(t, "otp-show-success")
	env.setupIDPWithMockProvider(t, "test-idp-show-ok", &mockProvider{id: "test-idp-show-ok"})

	addr, stop := fakeSMTPServerHandler(t)
	defer stop()

	host, port, _ := net.SplitHostPort(addr)
	smtpCfg := map[string]any{
		"host":         host,
		"port":         port,
		"from_address": "from@example.com",
		"enabled":      true,
	}
	smtpJSON, _ := json.Marshal(smtpCfg)
	if err := env.db.SaveSMTPConfig(context.Background(), &db.SMTPConfig{ConfigJSON: string(smtpJSON)}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	cookies := env.createSession(t, "provider", "test-idp-show-ok", "jdoe")
	rec := env.serveWithSession(t, env.handler.ShowMFA, http.MethodGet, "/mfa", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (OTP form rendered), got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ============================================================
// completeMFA — UpdateSessionMFA error (just logs, still redirects).
// ============================================================

func TestCompleteMFA_UpdateSessionMFAError(t *testing.T) {
	env := setupMFAHandlerTest(t)

	mockStore := &mockUpdateSessionMFAErrStore{DB: env.db, err: fmt.Errorf("db error")}
	h := env.newHandlerWithStore(t, mockStore)

	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")

	var redirectLoc string
	checkHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := auth.SessionFromContext(r.Context())
		h.completeMFA(w, r, sess)
		redirectLoc = w.Header().Get("Location")
	})
	env.serveWithSession(t, checkHandler, http.MethodPost, "/mfa/verify-otp", cookies, "")

	// completeMFA logs the error but still redirects to /dashboard.
	if redirectLoc != "/dashboard" {
		t.Errorf("expected /dashboard even with UpdateSessionMFA error, got %s", redirectLoc)
	}
}

// ============================================================
// ResendOTP — Duo provider (not emailotp), UpdateSessionMFA fails, sendEmail fails, success.
// ============================================================

func TestResendOTP_DuoProvider(t *testing.T) {
	// Duo provider → client is not *emailotp.Client → redirect to /mfa.
	env := setupMFAHandlerTest(t)
	env.setupDuoProvider(t, "duo-resend")

	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")
	rec := env.serveWithSession(t, env.handler.ResendOTP, http.MethodPost, "/mfa/resend-otp", cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/mfa" {
		t.Errorf("expected /mfa, got %s", loc)
	}
}

func TestResendOTP_UpdateSessionMFAFails(t *testing.T) {
	// Email OTP Initiate succeeds, but UpdateSessionMFA fails → flash + redirect to errorRedirect.
	env := setupMFAHandlerTest(t)
	env.setupEmailOTPProvider(t, "otp-resend-updsess")

	mockStore := &mockUpdateSessionMFAErrStore{DB: env.db, err: fmt.Errorf("db error")}
	h := env.newHandlerWithStore(t, mockStore)

	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")
	rec := env.serveWithSession(t, h.ResendOTP, http.MethodPost, "/mfa/resend-otp", cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected /dashboard, got %s", loc)
	}
}

func TestResendOTP_SendEmailFails(t *testing.T) {
	// Email OTP + IDP in registry/DB + no SMTP → sendOTPEmail fails → redirect.
	env := setupMFAHandlerTest(t)
	env.setupEmailOTPProvider(t, "otp-resend-emailfail")
	env.setupIDPWithMockProvider(t, "test-idp-resend-fail", &mockProvider{id: "test-idp-resend-fail"})

	// No SMTP configured → sendOTPEmail returns error.
	cookies := env.createSession(t, "provider", "test-idp-resend-fail", "jdoe")
	rec := env.serveWithSession(t, env.handler.ResendOTP, http.MethodPost, "/mfa/resend-otp", cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected /dashboard, got %s", loc)
	}
}

func TestResendOTP_Success(t *testing.T) {
	// Email OTP + IDP in registry/DB + working SMTP → renders OTP form (200).
	env := setupMFAHandlerTest(t)
	env.setupEmailOTPProvider(t, "otp-resend-success")
	env.setupIDPWithMockProvider(t, "test-idp-resend-ok", &mockProvider{id: "test-idp-resend-ok"})

	addr, stop := fakeSMTPServerHandler(t)
	defer stop()

	host, port, _ := net.SplitHostPort(addr)
	smtpCfg := map[string]any{
		"host":         host,
		"port":         port,
		"from_address": "from@example.com",
		"enabled":      true,
	}
	smtpJSON, _ := json.Marshal(smtpCfg)
	if err := env.db.SaveSMTPConfig(context.Background(), &db.SMTPConfig{ConfigJSON: string(smtpJSON)}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	cookies := env.createSession(t, "provider", "test-idp-resend-ok", "jdoe")
	rec := env.serveWithSession(t, env.handler.ResendOTP, http.MethodPost, "/mfa/resend-otp", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (OTP form rendered), got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ============================================================
// VerifyOTP — Duo provider (not emailotp), expired code path.
// ============================================================

func TestVerifyOTP_DuoProvider(t *testing.T) {
	// Duo configured → client is not *emailotp.Client → redirect to /mfa.
	env := setupMFAHandlerTest(t)
	env.setupDuoProvider(t, "duo-verify-otp")

	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")
	rec := env.serveWithSession(t, env.handler.VerifyOTP, http.MethodPost, "/mfa/verify-otp", cookies, "code=123456")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/mfa" {
		t.Errorf("expected /mfa, got %s", loc)
	}
}

func TestVerifyOTP_ExpiredCode(t *testing.T) {
	// Email OTP, session MFAState has Unix epoch expiry → Verify returns "expired" error.
	env := setupMFAHandlerTest(t)
	env.setupEmailOTPProvider(t, "otp-verify-expired")

	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")
	sessID := env.getSessionID(t, cookies)
	if sessID == "" {
		t.Skip("could not obtain session ID")
	}

	// Set expired OTP state: expiry timestamp 0 (Unix epoch, long past).
	expiredState := "otp:123456:0"
	if err := env.db.UpdateSessionMFA(context.Background(), sessID, true, expiredState); err != nil {
		t.Fatalf("setting session MFA state: %v", err)
	}

	rec := env.serveWithSession(t, env.handler.VerifyOTP, http.MethodPost, "/mfa/verify-otp", cookies, "code=123456")

	// Should re-render OTP form (200) with error about expiry.
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (OTP form re-render on expired), got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "expired") {
		t.Errorf("expected 'expired' in response, got: %s", rec.Body.String())
	}
}

// ============================================================
// Callback — Verify fails (expired OTP state via email OTP client).
// ============================================================

func TestCallback_VerifyFails(t *testing.T) {
	// Email OTP provider, state matches but code is expired → Verify fails → redirect.
	env := setupMFAHandlerTest(t)
	env.setupEmailOTPProvider(t, "otp-callback-verifyfail")

	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")
	sessID := env.getSessionID(t, cookies)
	if sessID == "" {
		t.Skip("could not obtain session ID")
	}

	// Set expired OTP state in session.
	expiredState := "otp:123456:0"
	if err := env.db.UpdateSessionMFA(context.Background(), sessID, true, expiredState); err != nil {
		t.Fatalf("setting session MFA state: %v", err)
	}

	// Call Callback with state matching the session and a valid-looking code.
	// The OTP is expired so Verify will fail regardless of the code.
	query := url.Values{
		"duo_code": {"123456"},
		"state":    {expiredState},
	}
	path := "/mfa/callback?" + query.Encode()
	rec := env.serveWithSession(t, env.handler.Callback, http.MethodGet, path, cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect on verify failure, got %d", rec.Code)
	}
	// Should redirect to errorRedirect (/dashboard for "provider" type).
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected /dashboard on failed verify, got %s", loc)
	}
}

// ============================================================
// Additional coverage tests
// ============================================================

// errReader always returns an error when Read() is called, used to trigger
// ParseForm failures by sending an unreadable request body.
type errReader struct{}

func (e errReader) Read(_ []byte) (int, error) { return 0, fmt.Errorf("read error") }

// TestBuildMFAClient_DuoNewError covers buildMFAClientForIDP when duo.New fails
// because the client_id length is not exactly 20 chars (mfa.go line 87).
func TestBuildMFAClient_DuoNewError(t *testing.T) {
	env := setupMFAHandlerTest(t)
	// Inject a DUO record with a client_id shorter than 20 chars → duo.New fails.
	mockStore := &mockMFAGetProviderStore{
		DB: env.db,
		record: &db.MFAProviderRecord{
			ID:           "duo-short-clientid",
			Name:         "Bad DUO",
			ProviderType: "duo",
			Enabled:      true,
			ConfigJSON:   `{"client_id":"tooshort","api_hostname":"api.duo.example.com","redirect_uri":"http://localhost/cb"}`,
		},
	}
	h := env.newHandlerWithStore(t, mockStore)
	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	_, _, err := h.buildMFAClient(req, "some-idp")
	if err == nil {
		t.Error("expected error for short DUO client_id, got nil")
	}
}

// TestBuildMFAClient_EmailConfigError covers buildMFAClientForIDP when the email
// OTP config JSON cannot be unmarshalled (mfa.go line 94).
func TestBuildMFAClient_EmailConfigError(t *testing.T) {
	env := setupMFAHandlerTest(t)
	mockStore := &mockMFAGetProviderStore{
		DB: env.db,
		record: &db.MFAProviderRecord{
			ID:           "email-bad-cfg",
			Name:         "Bad Email",
			ProviderType: "email",
			Enabled:      true,
			ConfigJSON:   "not-valid-json{{",
		},
	}
	h := env.newHandlerWithStore(t, mockStore)
	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	_, _, err := h.buildMFAClient(req, "some-idp")
	if err == nil {
		t.Error("expected error for invalid email OTP config JSON, got nil")
	}
}

// TestCallback_ResetType_MissingParams covers Callback when UserType is "reset"
// and required query params are missing → errorRedirect = "/forgot-password" (mfa.go line 268).
func TestCallback_ResetType_MissingParams(t *testing.T) {
	env := setupMFAHandlerTest(t)
	cookies := env.createSession(t, "reset", "corp-ad", "jdoe")

	rec := env.serveWithSession(t, env.handler.Callback, http.MethodGet, "/mfa/callback", cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/forgot-password" {
		t.Errorf("expected /forgot-password for reset session, got %s", loc)
	}
}

// TestVerifyOTP_ParseFormError covers VerifyOTP when ParseForm fails due to
// an unreadable body (mfa.go lines 330-333).
func TestVerifyOTP_ParseFormError(t *testing.T) {
	env := setupMFAHandlerTest(t)
	env.setupEmailOTPProvider(t, "otp-parsefail")

	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")

	// Build request with errReader body and application/x-www-form-urlencoded.
	req := httptest.NewRequest(http.MethodPost, "/mfa/verify-otp", errReader{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	wrapped := env.sm.Middleware(http.HandlerFunc(env.handler.VerifyOTP))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for ParseForm error, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestVerifyOTP_Success covers VerifyOTP when the OTP code is correct
// → completeMFA is called (mfa.go line 370).
func TestVerifyOTP_Success(t *testing.T) {
	env := setupMFAHandlerTest(t)
	env.setupEmailOTPProvider(t, "otp-verify-success")

	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")
	sessID := env.getSessionID(t, cookies)
	if sessID == "" {
		t.Skip("could not obtain session ID")
	}

	// Build a valid (non-expired) OTP state with a known code.
	// State format: "otp:<code>:<unix_expiry>" — far future expiry.
	futureExpiry := time.Now().Add(10 * time.Minute).Unix()
	validState := fmt.Sprintf("otp:999888:%d", futureExpiry)
	if err := env.db.UpdateSessionMFA(context.Background(), sessID, true, validState); err != nil {
		t.Fatalf("setting session MFA state: %v", err)
	}

	rec := env.serveWithSession(t, env.handler.VerifyOTP, http.MethodPost, "/mfa/verify-otp", cookies, "code=999888")

	// completeMFA redirects to /dashboard for "provider" user type.
	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect on success, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected /dashboard redirect, got %s", loc)
	}
}

// TestBuildEmailConfigFromRecord_DecryptError covers buildEmailConfigFromRecord
// when decrypting the SecretBlob fails (mfa.go lines 512-513).
func TestBuildEmailConfigFromRecord_DecryptError(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	cryptoSvc, err := crypto.NewService(key, 1)
	if err != nil {
		t.Fatalf("creating crypto service: %v", err)
	}

	configFields := map[string]any{
		"host": "smtp.example.com", "port": "587",
		"from_address": "no-reply@example.com",
		"enabled":      true,
	}
	cfgJSON, _ := json.Marshal(configFields)

	rec := &db.SMTPConfig{
		ConfigJSON: string(cfgJSON),
		SecretBlob: []byte("not-a-valid-ciphertext"),
	}

	_, buildErr := buildEmailConfigFromRecord(rec, cryptoSvc)
	if buildErr == nil {
		t.Error("expected error when SecretBlob cannot be decrypted, got nil")
	}
}

// ============================================================
// VerifyOTP — attempt limiting (3 strikes then token is dead)
// ============================================================

// makeOTPState constructs a valid OTP state string for a known code.
func makeOTPState(code string) string {
	expiry := time.Now().Add(5 * time.Minute).Unix()
	return fmt.Sprintf("otp:%s:%d", code, expiry)
}

func TestVerifyOTP_AttemptCounter_IncrementOnFail(t *testing.T) {
	// Submit a wrong code once. The handler should render "2 attempt(s) remaining"
	// and the DB should show mfa_attempts == 1.
	env := setupMFAHandlerTest(t)
	env.setupEmailOTPProvider(t, "otp-attempt-inc")

	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")
	sessID := env.getSessionID(t, cookies)
	if sessID == "" {
		t.Skip("could not obtain session ID")
	}

	state := makeOTPState("123456")
	if err := env.db.UpdateSessionMFA(context.Background(), sessID, true, state); err != nil {
		t.Fatalf("setting MFA state: %v", err)
	}

	rec := env.serveWithSession(t, env.handler.VerifyOTP, http.MethodPost, "/mfa/verify-otp", cookies, "code=000000")

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (re-render), got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "2 attempt(s) remaining") {
		t.Errorf("expected '2 attempt(s) remaining' in body, got: %s", rec.Body.String())
	}

	sess, err := env.db.GetSession(context.Background(), sessID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if sess.MFAAttempts != 1 {
		t.Errorf("expected mfa_attempts=1 after first fail, got %d", sess.MFAAttempts)
	}
}

func TestVerifyOTP_AttemptCounter_KillsTokenAfterMaxAttempts(t *testing.T) {
	// Pre-set mfa_attempts to mfaMaxAttempts-1 (2), then submit one more wrong code.
	// The token should be cleared and the response should say "Too many failed attempts".
	env := setupMFAHandlerTest(t)
	env.setupEmailOTPProvider(t, "otp-attempt-kill")

	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")
	sessID := env.getSessionID(t, cookies)
	if sessID == "" {
		t.Skip("could not obtain session ID")
	}

	state := makeOTPState("123456")
	if err := env.db.UpdateSessionMFA(context.Background(), sessID, true, state); err != nil {
		t.Fatalf("setting MFA state: %v", err)
	}
	// Pre-set to 2 prior failures.
	if err := env.db.UpdateSessionMFAAttempts(context.Background(), sessID, mfaMaxAttempts-1); err != nil {
		t.Fatalf("setting mfa_attempts: %v", err)
	}

	// Submit wrong code — this is the 3rd (fatal) attempt.
	rec := env.serveWithSession(t, env.handler.VerifyOTP, http.MethodPost, "/mfa/verify-otp", cookies, "code=000000")

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (re-render), got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Too many failed attempts") {
		t.Errorf("expected 'Too many failed attempts' in body, got: %s", rec.Body.String())
	}

	// MFA state and pending should be cleared; attempts reset to 0.
	sess, err := env.db.GetSession(context.Background(), sessID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if sess.MFAPending {
		t.Error("expected mfa_pending=false after token kill, got true")
	}
	if sess.MFAState != "" {
		t.Errorf("expected empty mfa_state after token kill, got %q", sess.MFAState)
	}
	if sess.MFAAttempts != 0 {
		t.Errorf("expected mfa_attempts=0 after token kill (reset by UpdateSessionMFA), got %d", sess.MFAAttempts)
	}
}

func TestVerifyOTP_AttemptCounter_SuccessOnPriorFails(t *testing.T) {
	// Pre-set mfa_attempts to 2 (two prior failures), then submit the correct code.
	// Verification should still succeed and MFA should be marked complete.
	env := setupMFAHandlerTest(t)
	env.setupEmailOTPProvider(t, "otp-attempt-ok")

	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")
	sessID := env.getSessionID(t, cookies)
	if sessID == "" {
		t.Skip("could not obtain session ID")
	}

	const code = "999888"
	state := makeOTPState(code)
	if err := env.db.UpdateSessionMFA(context.Background(), sessID, true, state); err != nil {
		t.Fatalf("setting MFA state: %v", err)
	}
	if err := env.db.UpdateSessionMFAAttempts(context.Background(), sessID, 2); err != nil {
		t.Fatalf("setting mfa_attempts: %v", err)
	}

	// Submit the correct code.
	rec := env.serveWithSession(t, env.handler.VerifyOTP, http.MethodPost, "/mfa/verify-otp", cookies, "code="+code)

	// Should redirect to /dashboard (completeMFA path).
	if rec.Code != http.StatusFound {
		t.Errorf("expected redirect on success, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected /dashboard, got %s", loc)
	}
}

func TestVerifyOTP_AttemptCounter_UpdateSessionMFAResetsCount(t *testing.T) {
	// Directly verify that UpdateSessionMFA resets mfa_attempts to 0, simulating
	// what happens when the user requests a new code via ResendOTP.
	database := setupTestDB(t)
	sm := auth.NewSessionManager(database, 30*time.Minute, false, testLogger())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	sessID, err := sm.CreateSession(w, r, "provider", "test-idp", "jdoe", false, false)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	ctx := context.Background()
	if err := database.UpdateSessionMFA(ctx, sessID, true, "otp:123456:9999999999"); err != nil {
		t.Fatalf("UpdateSessionMFA: %v", err)
	}
	if err := database.UpdateSessionMFAAttempts(ctx, sessID, 2); err != nil {
		t.Fatalf("UpdateSessionMFAAttempts: %v", err)
	}

	// Simulate ResendOTP issuing a new code (UpdateSessionMFA with a fresh state).
	if err := database.UpdateSessionMFA(ctx, sessID, true, "otp:654321:9999999999"); err != nil {
		t.Fatalf("UpdateSessionMFA (resend): %v", err)
	}

	sess, err := database.GetSession(ctx, sessID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if sess.MFAAttempts != 0 {
		t.Errorf("expected mfa_attempts=0 after UpdateSessionMFA (resend), got %d", sess.MFAAttempts)
	}
}

// TestShowMFA_EmailOTP_ReuseExistingState covers the OTP reuse path in ShowMFA
// (mfa.go lines 215-218). When a session already holds a valid unexpired OTP
// state, ShowMFA re-renders the form without generating a new code or sending
// another email.
func TestShowMFA_EmailOTP_ReuseExistingState(t *testing.T) {
	env := setupMFAHandlerTest(t)
	env.setupEmailOTPProvider(t, "email-otp-reuse")

	cookies := env.createSession(t, "provider", "corp-ad", "jdoe")
	sessID := env.getSessionID(t, cookies)
	if sessID == "" {
		t.Skip("could not obtain session ID")
	}

	// Set a valid, unexpired OTP state so emailotp.IsStateValid returns true.
	state := makeOTPState("123456")
	if err := env.db.UpdateSessionMFA(context.Background(), sessID, true, state); err != nil {
		t.Fatalf("setting MFA state: %v", err)
	}

	// GET /mfa — must re-render the OTP form (200) without generating a new code.
	rec := env.serveWithSession(t, env.handler.ShowMFA, http.MethodGet, "/mfa", cookies, "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (OTP reuse re-render), got %d; body: %s", rec.Code, rec.Body.String())
	}
}
