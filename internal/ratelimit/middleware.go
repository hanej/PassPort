package ratelimit

import (
	"encoding/json"
	"net"
	"net/http"
)

// KeyFunc extracts a rate-limiting key from an HTTP request.
type KeyFunc func(r *http.Request) string

// KeyByIP returns the client IP address from the request's RemoteAddr.
//
// This intentionally does NOT read X-Forwarded-For directly — trusting a
// client-supplied header here would let anyone bypass per-IP rate limiting
// simply by rotating its value. When PassPort is deployed behind a trusted
// reverse proxy (trust_proxy: true in config.yaml), handler.NewRouter wires
// up middleware that resolves the real client IP from X-Forwarded-For and
// mirrors it into RemoteAddr before this key function ever runs.
func KeyByIP(r *http.Request) string {
	// RemoteAddr is host:port; strip the port.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// KeyByUsername returns the "username" form value from the request.
func KeyByUsername(r *http.Request) string {
	return r.FormValue("username")
}

// Middleware returns chi-compatible middleware that rate-limits requests using
// the provided limiter and key function. When the limit is exceeded it responds
// with 429 Too Many Requests and a JSON error body.
func Middleware(limiter *Limiter, keyFn KeyFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFn(r)
			if !limiter.Allow(key) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "rate limit exceeded",
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
