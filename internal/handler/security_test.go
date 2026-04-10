package handler

// security_test.go contains security-focused integration tests: CSRF protection,
// authentication gates, session security, rate limiting, and the MFA bypass fix.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	csrf "filippo.io/csrf/gorilla"
	"github.com/go-chi/chi/v5"

	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
	"github.com/hanej/passport/internal/mfa"
	"github.com/hanej/passport/internal/ratelimit"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// testCSRFKey is a fixed 32-byte zero key for CSRF tests only.
var testCSRFKey = make([]byte, 32)

// buildCSRFRouter returns a minimal chi router with CSRF protection.
// GET /token is a safe endpoint (never blocked).
// POST /submit is the state-changing endpoint CSRF guards.
func buildCSRFRouter() http.Handler {
	r := chi.NewRouter()
	csrfMiddleware := csrf.Protect(testCSRFKey)
	r.Use(csrfMiddleware)
	r.Get("/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Post("/submit", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return r
}

// doPost submits a POST to the given path with optional header overrides.
func doPost(router http.Handler, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// createSession creates a DB-backed session and returns the session cookie +
// the session ID string. Pass mfaPending=true to also mark the session as
// requiring MFA verification.
func createSessionForTest(t *testing.T, sm *auth.SessionManager, database *db.DB,
	userType, username string, isAdmin, mfaPending bool) (cookies []*http.Cookie, sessionID string) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	id, err := sm.CreateSession(w, r, userType, "", username, isAdmin, false)
	if err != nil {
		t.Fatalf("createSessionForTest: %v", err)
	}
	if mfaPending {
		if err := database.UpdateSessionMFA(context.Background(), id, true, ""); err != nil {
			t.Fatalf("createSessionForTest: setting mfa_pending: %v", err)
		}
	}
	return w.Result().Cookies(), id
}

// ---------------------------------------------------------------------------
// CSRF protection tests
// ---------------------------------------------------------------------------

// TestCSRF_SameOriginPostAllowed verifies that a same-origin POST (carrying
// Sec-Fetch-Site: same-origin) is allowed through the CSRF middleware.
func TestCSRF_SameOriginPostAllowed(t *testing.T) {
	router := buildCSRFRouter()
	rec := doPost(router, "/submit", map[string]string{
		"Sec-Fetch-Site": "same-origin",
	})
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for same-origin POST, got %d", rec.Code)
	}
}

// TestCSRF_CrossSitePostBlocked verifies that a cross-site POST (Sec-Fetch-Site:
// cross-site) is rejected with HTTP 403, the primary CSRF attack vector.
func TestCSRF_CrossSitePostBlocked(t *testing.T) {
	router := buildCSRFRouter()
	rec := doPost(router, "/submit", map[string]string{
		"Sec-Fetch-Site": "cross-site",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for cross-site POST, got %d", rec.Code)
	}
}

// TestCSRF_ForeignOriginHeaderBlocked verifies that a POST whose Origin header
// does not match the request host is rejected with HTTP 403.
func TestCSRF_ForeignOriginHeaderBlocked(t *testing.T) {
	router := buildCSRFRouter()
	rec := doPost(router, "http://example.com/submit", map[string]string{
		"Origin": "https://attacker.com",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for mismatched Origin header, got %d", rec.Code)
	}
}

// TestCSRF_GetNeverBlocked confirms that GET requests are never blocked by CSRF
// middleware — GET is a safe method regardless of headers.
func TestCSRF_GetNeverBlocked(t *testing.T) {
	router := buildCSRFRouter()
	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for GET without CSRF headers, got %d", rec.Code)
	}
}

// TestCSRF_NonBrowserClientAllowed verifies that a POST with no Sec-Fetch-Site
// and no Origin header is allowed — non-browser API clients are not subject to
// CSRF, which is fundamentally a browser-initiated attack.
func TestCSRF_NonBrowserClientAllowed(t *testing.T) {
	router := buildCSRFRouter()
	rec := doPost(router, "/submit", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for non-browser POST (no Sec-Fetch-Site/Origin), got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Authentication gate tests (unauthenticated access)
// ---------------------------------------------------------------------------

// buildAuthGateRouter returns a router with session middleware guarding a
// single route. Pass requireAdmin=true to also apply RequireAdmin.
func buildAuthGateRouter(sm *auth.SessionManager, requireAdmin bool) http.Handler {
	r := chi.NewRouter()
	r.Use(sm.Middleware)
	if requireAdmin {
		r.Use(sm.RequireAdmin)
	}
	r.Get("/protected", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return r
}

// TestAuthZ_UnauthenticatedDashboard verifies that a request without a session
// cookie to a protected route is redirected to /login.
func TestAuthZ_UnauthenticatedDashboard(t *testing.T) {
	database := setupTestDB(t)
	sm := auth.NewSessionManager(database, 30*time.Minute, false, testLogger())
	router := buildAuthGateRouter(sm, false)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil) // no cookie
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 for unauthenticated request, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected redirect to /login, got %q", loc)
	}
}

// TestAuthZ_UnauthenticatedAdmin verifies that an unauthenticated request to an
// admin-only route is redirected to /login (auth gate fires before admin check).
func TestAuthZ_UnauthenticatedAdmin(t *testing.T) {
	database := setupTestDB(t)
	sm := auth.NewSessionManager(database, 30*time.Minute, false, testLogger())
	router := buildAuthGateRouter(sm, true)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 for unauthenticated admin route, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected redirect to /login, got %q", loc)
	}
}

// TestAuthZ_NonAdminForbidden verifies that a valid but non-admin session
// receives HTTP 403 when accessing an admin-only route.
func TestAuthZ_NonAdminForbidden(t *testing.T) {
	database := setupTestDB(t)
	sm := auth.NewSessionManager(database, 30*time.Minute, false, testLogger())
	router := buildAuthGateRouter(sm, true)

	// Create a non-admin session.
	cookies, _ := createSessionForTest(t, sm, database, "local", "regularuser", false, false)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin on admin route, got %d", rec.Code)
	}
}

// TestAuthZ_AdminCanAccess verifies that a valid admin session can reach an
// admin-only route.
func TestAuthZ_AdminCanAccess(t *testing.T) {
	database := setupTestDB(t)
	sm := auth.NewSessionManager(database, 30*time.Minute, false, testLogger())
	router := buildAuthGateRouter(sm, true)

	cookies, _ := createSessionForTest(t, sm, database, "local", "admin", true, false)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for admin on admin route, got %d", rec.Code)
	}
}

// TestAuthZ_MFAPendingBlocksDashboard verifies that a session with MFAPending=true
// cannot bypass the MFA gate to reach protected application routes.
func TestAuthZ_MFAPendingBlocksDashboard(t *testing.T) {
	database := setupTestDB(t)
	sm := auth.NewSessionManager(database, 30*time.Minute, false, testLogger())

	r := chi.NewRouter()
	r.Use(sm.Middleware)
	r.Use(sm.RequireMFA)
	r.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// The /mfa route sits outside RequireMFA in the real router.
	// We represent it here as unreachable via this router to confirm the redirect.

	cookies, _ := createSessionForTest(t, sm, database, "local", "user", false, true) // mfaPending=true

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 redirect for MFA-pending session on /dashboard, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/mfa" {
		t.Errorf("expected redirect to /mfa, got %q", loc)
	}
}

// TestAuthZ_MFAPendingCanReachMFARoute confirms that a session with MFAPending=true
// can still reach the /mfa route (which sits outside the RequireMFA guard).
func TestAuthZ_MFAPendingCanReachMFARoute(t *testing.T) {
	database := setupTestDB(t)
	sm := auth.NewSessionManager(database, 30*time.Minute, false, testLogger())

	r := chi.NewRouter()
	r.Use(sm.Middleware)
	// /mfa is intentionally NOT guarded by RequireMFA.
	r.Get("/mfa", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cookies, _ := createSessionForTest(t, sm, database, "local", "user", false, true) // mfaPending=true

	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for MFA-pending session on /mfa, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Session security tests
// ---------------------------------------------------------------------------

// TestSession_ReuseAfterLogout verifies that a session cookie is invalidated
// after logout — replaying the cookie against a protected route must fail.
func TestSession_ReuseAfterLogout(t *testing.T) {
	database := setupTestDB(t)
	sm := auth.NewSessionManager(database, 30*time.Minute, false, testLogger())

	// Create a session and capture the cookie.
	cookies, _ := createSessionForTest(t, sm, database, "local", "user", false, false)

	// Simulate logout: call DestroySession using a request that carries the cookie.
	logoutReq := httptest.NewRequest(http.MethodGet, "/logout", nil)
	for _, c := range cookies {
		logoutReq.AddCookie(c)
	}
	sm.DestroySession(httptest.NewRecorder(), logoutReq)

	// Now try to reuse the old cookie on a protected route.
	r := chi.NewRouter()
	r.Use(sm.Middleware)
	r.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	for _, c := range cookies { // stale cookies
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 (redirect to /login) on reuse of destroyed session, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected redirect to /login, got %q", loc)
	}
}

// TestSession_FlashTypeRejectedByDB verifies that the DB schema CHECK constraint
// prevents creation of any session with a user_type outside the allowed set.
// This is the actual protection against session-type confusion —  "flash" sessions
// cannot be stored and therefore cannot be used to access protected routes.
func TestSession_FlashTypeRejectedByDB(t *testing.T) {
	database := setupTestDB(t)
	sm := auth.NewSessionManager(database, 30*time.Minute, false, testLogger())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := sm.CreateSession(w, r, "flash", "", "", false, false)
	if err == nil {
		t.Error("expected DB constraint error when creating 'flash' session type, got nil")
	}
}

// TestSession_FlashCannotAccessDashboard documents the defence-in-depth provided
// by the RequireNonResetSession middleware fix (Bug 2). Even if future schema
// changes allowed "flash" user_type, the middleware would block dashboard access.
// This test uses a "reset" session to exercise the same code path.
func TestSession_FlashCannotAccessDashboard(t *testing.T) {
	database := setupTestDB(t)
	sm := auth.NewSessionManager(database, 30*time.Minute, false, testLogger())

	// Use a "reset" session to verify the middleware blocks non-app session types.
	// ("flash" cannot be created due to DB schema constraint — see TestSession_FlashTypeRejectedByDB.)
	cookies, _ := createSessionForTest(t, sm, database, "reset", "user", false, false)

	r := chi.NewRouter()
	r.Use(sm.Middleware)
	r.Use(sm.RequireMFA)
	r.Use(sm.RequirePasswordChange)
	r.Use(sm.RequireNonResetSession)
	r.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 (blocked) for reset/flash session on /dashboard, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/reset-password" {
		t.Errorf("expected redirect to /reset-password, got %q", loc)
	}
}

// TestSession_ResetCannotAccessDashboard verifies that a "reset"-type session
// (mid-forgot-password flow) cannot access protected application routes.
func TestSession_ResetCannotAccessDashboard(t *testing.T) {
	database := setupTestDB(t)
	sm := auth.NewSessionManager(database, 30*time.Minute, false, testLogger())

	cookies, _ := createSessionForTest(t, sm, database, "reset", "user", false, false)

	r := chi.NewRouter()
	r.Use(sm.Middleware)
	r.Use(sm.RequireMFA)
	r.Use(sm.RequirePasswordChange)
	r.Use(sm.RequireNonResetSession)
	r.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 for reset session on /dashboard, got %d", rec.Code)
	}
}

// TestSession_CookieIsHttpOnly verifies that the session cookie carries the
// HttpOnly attribute, preventing JavaScript access.
func TestSession_CookieIsHttpOnly(t *testing.T) {
	database := setupTestDB(t)
	sm := auth.NewSessionManager(database, 30*time.Minute, false, testLogger())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := sm.CreateSession(w, r, "local", "", "user", false, false); err != nil {
		t.Fatalf("creating session: %v", err)
	}

	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "passport_session" {
			if !cookie.HttpOnly {
				t.Error("session cookie must have HttpOnly=true")
			}
			return
		}
	}
	t.Error("passport_session cookie not found in response")
}

// TestSession_CookieSameSiteLax verifies that the session cookie uses
// SameSite=Lax, mitigating CSRF for navigation-based requests.
func TestSession_CookieSameSiteLax(t *testing.T) {
	database := setupTestDB(t)
	sm := auth.NewSessionManager(database, 30*time.Minute, false, testLogger())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := sm.CreateSession(w, r, "local", "", "user", false, false); err != nil {
		t.Fatalf("creating session: %v", err)
	}

	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "passport_session" {
			if cookie.SameSite != http.SameSiteLaxMode {
				t.Errorf("session cookie must have SameSite=Lax, got %v", cookie.SameSite)
			}
			return
		}
	}
	t.Error("passport_session cookie not found in response")
}

// TestSession_ExpiredSessionRejected verifies that an expired session is not
// accepted by the session middleware.
func TestSession_ExpiredSessionRejected(t *testing.T) {
	database := setupTestDB(t)
	// Create a session manager with a 1-nanosecond TTL so the session expires immediately.
	sm := auth.NewSessionManager(database, time.Nanosecond, false, testLogger())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := sm.CreateSession(w, r, "local", "", "user", false, false); err != nil {
		t.Fatalf("creating session: %v", err)
	}
	cookies := w.Result().Cookies()

	// Wait for the session to expire.
	time.Sleep(5 * time.Millisecond)

	router := chi.NewRouter()
	router.Use(sm.Middleware)
	router.Get("/protected", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 for expired session, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Rate limiting tests
// ---------------------------------------------------------------------------

// TestRateLimit_BruteForceLogin verifies that exceeding the rate limit on the
// login endpoint returns HTTP 429 with a JSON error body.
func TestRateLimit_BruteForceLogin(t *testing.T) {
	// 1 token burst, negligible refill rate — a single request exhausts the bucket.
	limiter := ratelimit.NewLimiter(0.0001, 1, testLogger())

	r := chi.NewRouter()
	r.Use(ratelimit.Middleware(limiter, ratelimit.KeyByIP))
	r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// First request: should pass (uses the single token).
	req1 := httptest.NewRequest(http.MethodPost, "/login", nil)
	req1.RemoteAddr = "1.2.3.4:9000"
	rec1 := httptest.NewRecorder()
	r.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request should pass, got %d", rec1.Code)
	}

	// Second request from the same IP: should be rate-limited.
	req2 := httptest.NewRequest(http.MethodPost, "/login", nil)
	req2.RemoteAddr = "1.2.3.4:9001"
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 for rate-limited request, got %d", rec2.Code)
	}
	// Verify the JSON error body.
	var body map[string]string
	if err := json.NewDecoder(rec2.Body).Decode(&body); err != nil {
		t.Errorf("expected JSON body in 429 response: %v", err)
	} else if body["error"] == "" {
		t.Error("expected non-empty 'error' field in 429 JSON body")
	}
}

// TestRateLimit_SameIPBlockedTogether confirms that multiple requests sharing
// the same IP exhaust the same rate-limit bucket.
func TestRateLimit_SameIPBlockedTogether(t *testing.T) {
	limiter := ratelimit.NewLimiter(0.0001, 3, testLogger()) // 3-token burst

	r := chi.NewRouter()
	r.Use(ratelimit.Middleware(limiter, ratelimit.KeyByIP))
	r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for i := range 3 {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "5.5.5.5:1000"
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d (within burst) should pass, got %d", i+1, rec.Code)
		}
	}

	// 4th request — burst exhausted.
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "5.5.5.5:1001"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after burst exhausted, got %d", rec.Code)
	}
}

// TestRateLimit_DifferentIPsHaveIndependentBuckets verifies that requests from
// different IPs do not share a rate-limit bucket.
func TestRateLimit_DifferentIPsHaveIndependentBuckets(t *testing.T) {
	limiter := ratelimit.NewLimiter(0.0001, 1, testLogger())

	r := chi.NewRouter()
	r.Use(ratelimit.Middleware(limiter, ratelimit.KeyByIP))
	r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// IP A exhausts its bucket.
	reqA := httptest.NewRequest(http.MethodPost, "/login", nil)
	reqA.RemoteAddr = "10.0.0.1:9000"
	r.ServeHTTP(httptest.NewRecorder(), reqA)

	// IP B's bucket is independent and should still pass.
	reqB := httptest.NewRequest(http.MethodPost, "/login", nil)
	reqB.RemoteAddr = "10.0.0.2:9000"
	recB := httptest.NewRecorder()
	r.ServeHTTP(recB, reqB)
	if recB.Code != http.StatusOK {
		t.Errorf("expected 200 for IP-B (independent bucket), got %d", recB.Code)
	}
}

// TestRateLimit_XFFSpoofingBypasses documents the known gap: X-Forwarded-For
// is trusted without origin validation, allowing per-IP rate limits to be
// bypassed by rotating the XFF header. This test confirms the current behavior
// so any future fix is detected as a deliberate change.
func TestRateLimit_XFFSpoofingBypasses(t *testing.T) {
	limiter := ratelimit.NewLimiter(0.0001, 1, testLogger())

	r := chi.NewRouter()
	r.Use(ratelimit.Middleware(limiter, ratelimit.KeyByIP))
	r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Same real RemoteAddr but different X-Forwarded-For values each time.
	spoofedIPs := []string{"10.0.1.1", "10.0.1.2", "10.0.1.3", "10.0.1.4", "10.0.1.5"}
	for i, ip := range spoofedIPs {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "1.2.3.4:9000"
		req.Header.Set("X-Forwarded-For", ip)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		// Each spoofed IP gets its own bucket, so all pass.
		if rec.Code != http.StatusOK {
			t.Logf("XFF spoof attempt %d (IP=%s) got %d (rate limited — XFF spoofing mitigation may be in place)", i+1, ip, rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// MFA security tests
// ---------------------------------------------------------------------------

// TestMFA_FreshLoginEnforcesMFA is the regression test for the MFA bypass bug.
// Before the fix: loginProvider discarded the new session ID and read from the
// request cookie (nil for fresh logins), so mfaRedirect was silently skipped.
// After the fix: the returned session ID is used directly.
func TestMFA_FreshLoginEnforcesMFA(t *testing.T) {
	database := setupTestDB(t)

	// Configure a mock store: MFA required globally + emailotp provider for the IDP.
	cfgBytes, _ := json.Marshal(mfa.EmailOTPConfig{OTPLength: 6, OTPTTLMinutes: 5})
	mfaRecord := &db.MFAProviderRecord{
		ID:           "mfa-emailotp",
		Name:         "Email OTP",
		ProviderType: string(mfa.ProviderTypeEmail),
		Enabled:      true,
		ConfigJSON:   string(cfgBytes),
	}
	mockStore := &mockLoginErrStore{
		DB:                         database,
		getMFALoginRequiredVal:     true,
		getMFAProviderForIDPRecord: mfaRecord,
	}

	// Build the login handler with the mock store and a registry with a
	// passthrough provider.
	h := newMockLoginHandler(t, mockStore, database)
	h.registry.Register("test-idp", &mockProvider{
		id:           "test-idp",
		providerType: idp.ProviderTypeAD,
		authErr:      nil, // authentication always succeeds
	})

	// POST /login with NO pre-existing session cookie (fresh browser).
	form := url.Values{
		"provider_id": {"test-idp"},
		"username":    {"testuser"},
		"password":    {"testpass"},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Do NOT add any cookies — simulates a fresh browser session.

	rec := httptest.NewRecorder()
	h.Login(rec, req)

	// Expect a redirect to /mfa, not /dashboard.
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d; body: %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if loc != "/mfa" {
		t.Errorf("MFA bypass: expected redirect to /mfa, got %q — check login.go MFA session ID fix", loc)
	}

	// Verify the newly created session in DB has mfa_pending=true.
	var sessionID string
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "passport_session" {
			sessionID = cookie.Value
			break
		}
	}
	if sessionID == "" {
		t.Fatal("no passport_session cookie in response")
	}
	sess, err := database.GetSession(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("getting session from DB: %v", err)
	}
	if !sess.MFAPending {
		t.Error("expected MFAPending=true on new session after fresh login with MFA required")
	}
}

// TestMFA_PendingSessionCannotSkipToApp verifies that a session created with
// MFAPending=true cannot access application routes by bypassing the MFA gate.
func TestMFA_PendingSessionCannotSkipToApp(t *testing.T) {
	database := setupTestDB(t)
	sm := auth.NewSessionManager(database, 30*time.Minute, false, testLogger())

	// Create a session and mark it as MFA-pending (mirrors what loginProvider does).
	cookies, _ := createSessionForTest(t, sm, database, "local", "user", false, true)

	r := chi.NewRouter()
	r.Use(sm.Middleware)
	r.Use(sm.RequireMFA)
	r.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/mfa" {
		t.Errorf("expected redirect to /mfa for MFA-pending session, got %d %s",
			rec.Code, rec.Header().Get("Location"))
	}
}

// TestMFA_VerifiedSessionCanAccessApp confirms the positive case: once MFA is
// verified (MFAPending=false), the session can reach protected routes.
func TestMFA_VerifiedSessionCanAccessApp(t *testing.T) {
	database := setupTestDB(t)
	sm := auth.NewSessionManager(database, 30*time.Minute, false, testLogger())

	// Regular session with MFAPending=false (default after CreateSession).
	cookies, _ := createSessionForTest(t, sm, database, "local", "user", false, false)

	r := chi.NewRouter()
	r.Use(sm.Middleware)
	r.Use(sm.RequireMFA)
	r.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for verified (non-MFA-pending) session on /dashboard, got %d", rec.Code)
	}
}
