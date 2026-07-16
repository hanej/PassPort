package ratelimit

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestMiddleware_PassesUnderLimit(t *testing.T) {
	l := NewLimiter(10, 5, slog.Default())

	handler := Middleware(l, KeyByIP)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}
}

func TestMiddleware_Returns429WhenLimitExceeded(t *testing.T) {
	l := NewLimiter(1, 2, slog.Default())

	handler := Middleware(l, KeyByIP)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust the burst.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:8080"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	// This request should be rate limited.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:8080"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if body["error"] != "rate limit exceeded" {
		t.Fatalf("expected error 'rate limit exceeded', got %q", body["error"])
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}
}

func TestKeyByIP_IgnoresXForwardedFor(t *testing.T) {
	// KeyByIP must not trust a client-supplied X-Forwarded-For header directly
	// — otherwise any client could bypass per-IP rate limiting by rotating it.
	// Real IP resolution only happens via the ClientIPFrom* + mirrorResolvedClientIP
	// middleware in handler.NewRouter, which is not present in this bare test setup.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18")
	req.RemoteAddr = "127.0.0.1:9999"

	key := KeyByIP(req)
	if key != "127.0.0.1" {
		t.Fatalf("expected RemoteAddr-derived '127.0.0.1' (XFF ignored), got %q", key)
	}
}

func TestKeyByIP_FallsBackToRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.100:54321"

	key := KeyByIP(req)
	if key != "192.168.1.100" {
		t.Fatalf("expected '192.168.1.100', got %q", key)
	}
}

func TestKeyByUsername_ExtractsFormValue(t *testing.T) {
	form := url.Values{"username": {"jdoe"}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	key := KeyByUsername(req)
	if key != "jdoe" {
		t.Fatalf("expected 'jdoe', got %q", key)
	}
}

func TestKeyByIP_IgnoresXForwardedForComma(t *testing.T) {
	// Same as above but with a multi-value XFF header — still ignored.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	req.RemoteAddr = "192.168.0.9:4321"

	key := KeyByIP(req)
	if key != "192.168.0.9" {
		t.Fatalf("expected RemoteAddr-derived '192.168.0.9' (XFF ignored), got %q", key)
	}
}

func TestKeyByIP_InvalidRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Override RemoteAddr with a value that has no port so net.SplitHostPort fails.
	req.RemoteAddr = "invalid"

	key := KeyByIP(req)
	if key != "invalid" {
		t.Fatalf("expected 'invalid', got %q", key)
	}
}
