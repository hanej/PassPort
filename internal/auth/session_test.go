package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hanej/passport/internal/db"
)

func newTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.OpenMemory()
	if err != nil {
		t.Fatalf("open memory db: %v", err)
	}
	if err := d.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func newTestManager(t *testing.T) (*SessionManager, *db.DB) {
	t.Helper()
	d := newTestDB(t)
	logger := slog.Default()
	sm := NewSessionManager(d, 30*time.Minute, false, logger)
	return sm, d
}

// addSessionCookie copies the Set-Cookie header from the recorder into a new request.
func addSessionCookie(rec *httptest.ResponseRecorder, r *http.Request) *http.Request {
	resp := rec.Result()
	for _, c := range resp.Cookies() {
		r.AddCookie(c)
	}
	return r
}

func TestCreateSession(t *testing.T) {
	sm, d := newTestManager(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.10:12345"
	req.Header.Set("User-Agent", "TestAgent/1.0")

	id, err := sm.CreateSession(rec, req, "local", "", "admin", true, false)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if len(id) != 64 {
		t.Errorf("expected 64-char session ID, got %d chars: %s", len(id), id)
	}

	// Verify cookie was set.
	resp := rec.Result()
	cookies := resp.Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == "passport_session" {
			found = true
			if c.Value != id {
				t.Errorf("cookie value = %s, want %s", c.Value, id)
			}
			if !c.HttpOnly {
				t.Error("cookie should be HttpOnly")
			}
			if c.Path != "/" {
				t.Errorf("cookie path = %s, want /", c.Path)
			}
		}
	}
	if !found {
		t.Fatal("passport_session cookie not set")
	}

	// Verify session in DB.
	sess, err := d.GetSession(context.Background(), id)
	if err != nil {
		t.Fatalf("GetSession from DB: %v", err)
	}
	if sess.Username != "admin" {
		t.Errorf("username = %s, want admin", sess.Username)
	}
	if !sess.IsAdmin {
		t.Error("expected IsAdmin = true")
	}
	if sess.IPAddress != "192.168.1.10" {
		t.Errorf("ip = %s, want 192.168.1.10", sess.IPAddress)
	}
	if sess.UserAgent != "TestAgent/1.0" {
		t.Errorf("user agent = %s, want TestAgent/1.0", sess.UserAgent)
	}
}

func TestCreateSessionXForwardedFor(t *testing.T) {
	sm, d := newTestManager(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")

	id, err := sm.CreateSession(rec, req, "provider", "okta", "user1", false, false)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sess, err := d.GetSession(context.Background(), id)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if sess.IPAddress != "10.0.0.1" {
		t.Errorf("ip = %s, want 10.0.0.1", sess.IPAddress)
	}
}

func TestGetSession(t *testing.T) {
	sm, _ := newTestManager(t)

	// Create a session first.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	id, err := sm.CreateSession(rec, req, "local", "", "admin", true, false)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Build a new request with the session cookie.
	req2 := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req2 = addSessionCookie(rec, req2)

	sess, err := sm.GetSession(req2)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if sess.ID != id {
		t.Errorf("session ID = %s, want %s", sess.ID, id)
	}
	if sess.Username != "admin" {
		t.Errorf("username = %s, want admin", sess.Username)
	}
}

func TestGetSessionMissingCookie(t *testing.T) {
	sm, _ := newTestManager(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := sm.GetSession(req)
	if err != ErrNoSession {
		t.Errorf("expected ErrNoSession, got %v", err)
	}
}

func TestGetSessionExpired(t *testing.T) {
	// Use a very short TTL so the session expires immediately.
	d := newTestDB(t)
	logger := slog.Default()
	sm := NewSessionManager(d, 1*time.Millisecond, false, logger)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := sm.CreateSession(rec, req, "local", "", "admin", true, false)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Wait for expiry.
	time.Sleep(5 * time.Millisecond)

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2 = addSessionCookie(rec, req2)

	_, err = sm.GetSession(req2)
	if err != ErrNoSession {
		t.Errorf("expected ErrNoSession for expired session, got %v", err)
	}
}

func TestGetSessionNotFound(t *testing.T) {
	sm, _ := newTestManager(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "passport_session", Value: "nonexistent-id"})

	_, err := sm.GetSession(req)
	if err != ErrNoSession {
		t.Errorf("expected ErrNoSession, got %v", err)
	}
}

func TestDestroySession(t *testing.T) {
	sm, d := newTestManager(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	id, err := sm.CreateSession(rec, req, "local", "", "admin", true, false)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Destroy the session.
	destroyRec := httptest.NewRecorder()
	destroyReq := httptest.NewRequest(http.MethodPost, "/logout", nil)
	destroyReq = addSessionCookie(rec, destroyReq)

	sm.DestroySession(destroyRec, destroyReq)

	// Verify cookie is cleared.
	resp := destroyRec.Result()
	for _, c := range resp.Cookies() {
		if c.Name == "passport_session" {
			if c.MaxAge != -1 {
				t.Errorf("cookie MaxAge = %d, want -1", c.MaxAge)
			}
		}
	}

	// Verify session is gone from DB.
	_, err = d.GetSession(context.Background(), id)
	if err == nil {
		t.Error("expected error getting deleted session")
	}
}

func TestMiddlewareRedirectsWithoutSession(t *testing.T) {
	sm, _ := newTestManager(t)

	handler := sm.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	loc := rec.Header().Get("Location")
	if loc != "/login" {
		t.Errorf("redirect location = %s, want /login", loc)
	}
}

func TestMiddlewareSetsContext(t *testing.T) {
	sm, _ := newTestManager(t)

	// Create a session.
	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := sm.CreateSession(createRec, createReq, "local", "", "testuser", false, false)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	var ctxSess *db.Session
	handler := sm.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxSess = SessionFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req = addSessionCookie(createRec, req)

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ctxSess == nil {
		t.Fatal("session not found in context")
	}
	if ctxSess.Username != "testuser" {
		t.Errorf("context username = %s, want testuser", ctxSess.Username)
	}
}

func TestRequireAdminForbidden(t *testing.T) {
	sm, _ := newTestManager(t)

	// Create a non-admin session.
	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := sm.CreateSession(createRec, createReq, "local", "", "user1", false, false)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// Chain: Middleware -> RequireAdmin -> handler
	handler := sm.Middleware(sm.RequireAdmin(inner))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req = addSessionCookie(createRec, req)

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestRequireAdminAllowed(t *testing.T) {
	sm, _ := newTestManager(t)

	// Create an admin session.
	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := sm.CreateSession(createRec, createReq, "local", "", "admin", true, false)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := sm.Middleware(sm.RequireAdmin(inner))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req = addSessionCookie(createRec, req)

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRequirePasswordChange(t *testing.T) {
	sm, _ := newTestManager(t)

	// Create a session that requires password change.
	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := sm.CreateSession(createRec, createReq, "local", "", "admin", true, true)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := sm.Middleware(sm.RequirePasswordChange(inner))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req = addSessionCookie(createRec, req)

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	loc := rec.Header().Get("Location")
	if loc != "/change-password" {
		t.Errorf("redirect location = %s, want /change-password", loc)
	}
}

func TestFlashRoundTrip(t *testing.T) {
	sm, _ := newTestManager(t)

	// Create a session.
	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := sm.CreateSession(createRec, createReq, "local", "", "admin", true, false)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Set flash.
	setReq := httptest.NewRequest(http.MethodGet, "/action", nil)
	setReq = addSessionCookie(createRec, setReq)
	setRec := httptest.NewRecorder()
	sm.SetFlash(setRec, setReq, "success", "Password changed")

	// Get flash.
	getReq := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	getReq = addSessionCookie(createRec, getReq)
	flash := sm.GetFlash(getReq)

	if flash == nil {
		t.Fatal("expected flash data, got nil")
	}
	if flash["category"] != "success" {
		t.Errorf("flash category = %s, want success", flash["category"])
	}
	if flash["message"] != "Password changed" {
		t.Errorf("flash message = %s, want 'Password changed'", flash["message"])
	}

	// Second read should return nil (flash was cleared).
	getReq2 := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	getReq2 = addSessionCookie(createRec, getReq2)
	flash2 := sm.GetFlash(getReq2)
	if flash2 != nil {
		t.Errorf("expected nil flash on second read, got %v", flash2)
	}
}

func TestStartPurge(t *testing.T) {
	d := newTestDB(t)
	sm := NewSessionManager(d, 30*time.Minute, false, slog.Default())

	// Create a session with a long TTL.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	id, err := sm.CreateSession(rec, req, "local", "", "admin", true, false)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Force expires_at into the past so the purge SQL will match it.
	// This avoids SQLite's second-level timestamp granularity being a factor.
	past := time.Now().UTC().Add(-10 * time.Second)
	if err := d.TouchSession(context.Background(), id, past); err != nil {
		t.Fatalf("forcing session expiry: %v", err)
	}

	// Start purge with a short interval and let a cycle fire.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sm.StartPurge(ctx, 50*time.Millisecond)
	time.Sleep(200 * time.Millisecond)

	// Session should be purged.
	_, err = d.GetSession(context.Background(), id)
	if err == nil {
		t.Error("expected session to be purged, but it still exists")
	}
}

func TestSessionFromContextNil(t *testing.T) {
	sess := SessionFromContext(context.Background())
	if sess != nil {
		t.Error("expected nil session from empty context")
	}
}

func TestTouchSession(t *testing.T) {
	d := newTestDB(t)
	logger := slog.Default()
	// Use a short TTL so Touch produces a visibly different expiry.
	sm := NewSessionManager(d, 10*time.Second, false, logger)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	id, err := sm.CreateSession(rec, req, "local", "", "admin", true, false)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessBefore, err := d.GetSession(context.Background(), id)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}

	// Wait just over one second so the new expiry timestamp (second-level
	// granularity in SQLite) is strictly after the original.
	time.Sleep(1100 * time.Millisecond)

	if err := sm.TouchSession(context.Background(), id); err != nil {
		t.Fatalf("TouchSession: %v", err)
	}

	sessAfter, err := d.GetSession(context.Background(), id)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}

	if !sessAfter.ExpiresAt.After(sessBefore.ExpiresAt) {
		t.Errorf("expected expiry to slide forward: before=%v, after=%v",
			sessBefore.ExpiresAt, sessAfter.ExpiresAt)
	}
}

func TestRequireNonResetSession_Redirects(t *testing.T) {
	sm, _ := newTestManager(t)

	// Create a "reset" type session.
	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := sm.CreateSession(createRec, createReq, "reset", "", "user1", false, false)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := sm.Middleware(sm.RequireNonResetSession(inner))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req = addSessionCookie(createRec, req)

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	loc := rec.Header().Get("Location")
	if loc != "/reset-password" {
		t.Errorf("redirect location = %s, want /reset-password", loc)
	}
}

func TestRequireNonResetSession_Passes(t *testing.T) {
	sm, _ := newTestManager(t)

	// Create a normal "provider" session.
	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := sm.CreateSession(createRec, createReq, "provider", "okta", "user1", false, false)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	var called bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := sm.Middleware(sm.RequireNonResetSession(inner))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req = addSessionCookie(createRec, req)

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !called {
		t.Error("expected next handler to be called")
	}
}

func TestUpdateSessionMustChangePassword(t *testing.T) {
	sm, d := newTestManager(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	id, err := sm.CreateSession(rec, req, "local", "", "admin", true, false)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if err := sm.UpdateSessionMustChangePassword(context.Background(), id, true); err != nil {
		t.Fatalf("UpdateSessionMustChangePassword: %v", err)
	}

	sess, err := d.GetSession(context.Background(), id)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if !sess.MustChangePassword {
		t.Error("expected MustChangePassword to be true")
	}
}

func TestDestroySessionNoCookie(t *testing.T) {
	sm, _ := newTestManager(t)

	// Request with no session cookie — exercises the err != nil branch in DestroySession.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)

	sm.DestroySession(rec, req)

	// The cookie should still be cleared (MaxAge=-1) even without an existing session.
	var found bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "passport_session" {
			found = true
			if c.MaxAge != -1 {
				t.Errorf("cookie MaxAge = %d, want -1", c.MaxAge)
			}
		}
	}
	if !found {
		t.Error("expected passport_session cookie set with MaxAge=-1")
	}
}

func TestGetFlashNoSession(t *testing.T) {
	sm, _ := newTestManager(t)

	// Request with no session cookie — exercises the err != nil early return in GetFlash.
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	flash := sm.GetFlash(req)
	if flash != nil {
		t.Errorf("expected nil flash for request with no session, got %v", flash)
	}
}

func TestSetFlashNoSession(t *testing.T) {
	sm, _ := newTestManager(t)

	// Request with no session cookie — exercises the err != nil early return in SetFlash.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/action", nil)

	// Must not panic; covers the fallback GetSession path returning an error.
	sm.SetFlash(rec, req, "success", "test message")
}

func TestCreateSessionXForwardedFor_Single(t *testing.T) {
	// X-Forwarded-For with a single IP (no comma) → uses the xff directly.
	sm, d := newTestManager(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1")

	id, err := sm.CreateSession(rec, req, "local", "", "admin", true, false)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sess, err := d.GetSession(context.Background(), id)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if sess.IPAddress != "203.0.113.1" {
		t.Errorf("ip = %s, want 203.0.113.1", sess.IPAddress)
	}
}

func TestCreateSessionRemoteAddrNoPort(t *testing.T) {
	// RemoteAddr without port → covers the fallback `return addr` branch in clientIP.
	sm, d := newTestManager(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Override RemoteAddr to have no port separator.
	req.RemoteAddr = "10.0.0.5"

	id, err := sm.CreateSession(rec, req, "local", "", "admin", true, false)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sess, err := d.GetSession(context.Background(), id)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if sess.IPAddress != "10.0.0.5" {
		t.Errorf("ip = %s, want 10.0.0.5", sess.IPAddress)
	}
}

func TestRequirePasswordChange_PassThrough(t *testing.T) {
	// MustChangePassword == false → next handler is called.
	sm, _ := newTestManager(t)

	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := sm.CreateSession(createRec, createReq, "local", "", "admin", true, false)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	handler := sm.Middleware(sm.RequirePasswordChange(inner))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req = addSessionCookie(createRec, req)

	handler.ServeHTTP(rec, req)

	if !reached {
		t.Error("inner handler was not reached")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// mockSessionStore embeds *db.DB and overrides specific methods to inject errors.
type mockSessionStore struct {
	*db.DB
	createSessionErr      error
	deleteSessionErr      error
	touchSessionErr       error
	updateSessionFlashErr error
	purgeExpiredErr       error
}

func (m *mockSessionStore) CreateSession(ctx context.Context, s *db.Session) error {
	if m.createSessionErr != nil {
		return m.createSessionErr
	}
	return m.DB.CreateSession(ctx, s)
}

func (m *mockSessionStore) DeleteSession(ctx context.Context, id string) error {
	if m.deleteSessionErr != nil {
		return m.deleteSessionErr
	}
	return m.DB.DeleteSession(ctx, id)
}

func (m *mockSessionStore) TouchSession(ctx context.Context, id string, expiresAt time.Time) error {
	if m.touchSessionErr != nil {
		return m.touchSessionErr
	}
	return m.DB.TouchSession(ctx, id, expiresAt)
}

func (m *mockSessionStore) UpdateSessionFlash(ctx context.Context, id, flashJSON string) error {
	if m.updateSessionFlashErr != nil {
		return m.updateSessionFlashErr
	}
	return m.DB.UpdateSessionFlash(ctx, id, flashJSON)
}

func (m *mockSessionStore) PurgeExpired(ctx context.Context) (int64, error) {
	if m.purgeExpiredErr != nil {
		return 0, m.purgeExpiredErr
	}
	return m.DB.PurgeExpired(ctx)
}

func newManagerWithMock(t *testing.T) (*SessionManager, *mockSessionStore) {
	t.Helper()
	d := newTestDB(t)
	mock := &mockSessionStore{DB: d}
	sm := NewSessionManager(mock, 30*time.Minute, false, slog.Default())
	return sm, mock
}

// TestCreateSession_StoreError covers CreateSession when the store fails to persist.
func TestCreateSession_StoreError(t *testing.T) {
	sm, mock := newManagerWithMock(t)
	mock.createSessionErr = fmt.Errorf("DB create failed")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := sm.CreateSession(rec, req, "local", "", "admin", true, false)
	if err == nil {
		t.Fatal("expected error when store.CreateSession fails")
	}
}

// TestStartPurge_PurgeError covers the error-logging branch inside the purge goroutine.
func TestStartPurge_PurgeError(t *testing.T) {
	sm, mock := newManagerWithMock(t)
	mock.purgeExpiredErr = fmt.Errorf("DB purge failed")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sm.StartPurge(ctx, 50*time.Millisecond)
	// Let at least one cycle fire the error-log path; must not panic.
	time.Sleep(150 * time.Millisecond)
}

// TestDestroySession_DeleteError covers lines 156-161 where DeleteSession fails.
// The cookie should still be cleared despite the DB error.
func TestDestroySession_DeleteError(t *testing.T) {
	sm, mock := newManagerWithMock(t)

	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := sm.CreateSession(createRec, createReq, "local", "", "admin", true, false); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	mock.deleteSessionErr = fmt.Errorf("DB delete failed")

	rec := httptest.NewRecorder()
	req := addSessionCookie(createRec, httptest.NewRequest(http.MethodPost, "/logout", nil))
	sm.DestroySession(rec, req)

	var found bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "passport_session" {
			found = true
			if c.MaxAge != -1 {
				t.Errorf("cookie MaxAge = %d, want -1", c.MaxAge)
			}
		}
	}
	if !found {
		t.Error("expected passport_session cookie cleared with MaxAge=-1")
	}
}

// TestMiddleware_TouchSessionError covers lines 201-206 where TouchSession fails.
// The next handler should still be called.
func TestMiddleware_TouchSessionError(t *testing.T) {
	sm, mock := newManagerWithMock(t)

	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := sm.CreateSession(createRec, createReq, "local", "", "admin", true, false); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	mock.touchSessionErr = fmt.Errorf("DB touch failed")

	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true })
	rec := httptest.NewRecorder()
	req := addSessionCookie(createRec, httptest.NewRequest(http.MethodGet, "/dashboard", nil))
	sm.Middleware(inner).ServeHTTP(rec, req)

	if !reached {
		t.Error("expected next handler to be called despite TouchSession error")
	}
}

// TestSetFlash_UpdateSessionFlashError covers lines 321-326 where UpdateSessionFlash fails.
// SetFlash must not panic.
func TestSetFlash_UpdateSessionFlashError(t *testing.T) {
	sm, mock := newManagerWithMock(t)

	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := sm.CreateSession(createRec, createReq, "local", "", "admin", true, false); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	mock.updateSessionFlashErr = fmt.Errorf("DB flash failed")

	rec := httptest.NewRecorder()
	req := addSessionCookie(createRec, httptest.NewRequest(http.MethodGet, "/action", nil))
	sm.SetFlash(rec, req, "success", "hello") // must not panic
}

// TestGetFlash_InvalidJSON covers lines 347-352 where FlashJSON is not valid JSON.
func TestGetFlash_InvalidJSON(t *testing.T) {
	sm, d := newTestManager(t)

	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodGet, "/", nil)
	id, err := sm.CreateSession(createRec, createReq, "local", "", "admin", true, false)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Directly write invalid JSON to FlashJSON.
	if err := d.UpdateSessionFlash(context.Background(), id, "not-json{"); err != nil {
		t.Fatalf("UpdateSessionFlash: %v", err)
	}

	req := addSessionCookie(createRec, httptest.NewRequest(http.MethodGet, "/dashboard", nil))
	flash := sm.GetFlash(req)
	if flash != nil {
		t.Errorf("expected nil flash for invalid JSON, got %v", flash)
	}
}

// TestGetFlash_UpdateSessionFlashError covers lines 355-360 where clearing the flash fails.
// GetFlash should still return the flash data.
func TestGetFlash_UpdateSessionFlashError(t *testing.T) {
	sm, mock := newManagerWithMock(t)

	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodGet, "/", nil)
	id, err := sm.CreateSession(createRec, createReq, "local", "", "admin", true, false)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Write valid flash JSON directly to the DB.
	flashJSON := `{"category":"success","message":"hello"}`
	if err := mock.DB.UpdateSessionFlash(context.Background(), id, flashJSON); err != nil {
		t.Fatalf("UpdateSessionFlash: %v", err)
	}

	// Make the clear-flash operation fail.
	mock.updateSessionFlashErr = fmt.Errorf("DB flash clear failed")

	// Fetch session from DB (no context session) so FlashJSON is populated.
	req := addSessionCookie(createRec, httptest.NewRequest(http.MethodGet, "/dashboard", nil))
	flash := sm.GetFlash(req)

	if flash == nil {
		t.Error("expected flash to be returned even when clearing fails")
	} else if flash["message"] != "hello" {
		t.Errorf("expected flash message 'hello', got %q", flash["message"])
	}
}

// TestRequireMFA_Redirects verifies that RequireMFA redirects when the session
// has MFAPending=true.
func TestRequireMFA_Redirects(t *testing.T) {
	sm, d := newTestManager(t)

	// Create a session.
	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodGet, "/", nil)
	id, err := sm.CreateSession(createRec, createReq, "local", "", "user", false, false)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Set MFAPending=true.
	if err := d.UpdateSessionMFA(context.Background(), id, true, ""); err != nil {
		t.Fatalf("UpdateSessionMFA: %v", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := sm.Middleware(sm.RequireMFA(next))
	req := addSessionCookie(createRec, httptest.NewRequest(http.MethodGet, "/dashboard", nil))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/mfa" {
		t.Errorf("expected redirect to /mfa, got %q", loc)
	}
	if called {
		t.Error("expected next handler not to be called")
	}
}

// TestRequireMFA_PassThrough verifies that RequireMFA calls next when
// MFAPending is false.
func TestRequireMFA_PassThrough(t *testing.T) {
	sm, _ := newTestManager(t)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	// Create a session (MFAPending defaults to false).
	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := sm.CreateSession(createRec, createReq, "local", "", "user", false, false); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	handler := sm.Middleware(sm.RequireMFA(next))
	req := addSessionCookie(createRec, httptest.NewRequest(http.MethodGet, "/dashboard", nil))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called")
	}
}
