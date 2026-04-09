package ratelimit

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

// KeyFunc extracts a rate-limiting key from an HTTP request.
type KeyFunc func(r *http.Request) string

// KeyByIP returns the client IP address, preferring the X-Forwarded-For header
// and falling back to the request's RemoteAddr.
func KeyByIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For may contain a comma-separated list; use the first entry.
		if i := strings.IndexByte(xff, ','); i != -1 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}

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
