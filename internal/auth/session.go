// Copyright 2026 Jason Hane
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package auth provides session management for the PassPort application.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/hanej/passport/internal/db"
)

// ErrNoSession is returned when no valid session exists (missing cookie, expired, or not found).
var ErrNoSession = fmt.Errorf("no valid session")

// contextKey is a type-safe key for storing sessions in request contexts.
type contextKey struct{}

// SessionManager wraps session operations backed by a SessionStore.
type SessionManager struct {
	store        db.SessionStore
	ttl          time.Duration
	cookieName   string
	secureCookie bool
	logger       *slog.Logger
}

// NewSessionManager creates a new SessionManager.
func NewSessionManager(store db.SessionStore, ttl time.Duration, secureCookie bool, logger *slog.Logger) *SessionManager {
	return &SessionManager{
		store:        store,
		ttl:          ttl,
		cookieName:   "passport_session",
		secureCookie: secureCookie,
		logger:       logger,
	}
}

// generateSessionID produces a cryptographically random 64-character hex string.
func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating session ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// clientIP extracts the client IP address from the request,
// preferring X-Forwarded-For if present.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain (the original client).
		if idx := strings.IndexByte(xff, ','); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	// Strip port from RemoteAddr.
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// CreateSession creates a new session in the database and sets an HTTP cookie
// on the response. It returns the session ID or an error.
func (sm *SessionManager) CreateSession(
	w http.ResponseWriter,
	r *http.Request,
	userType string,
	providerID string,
	username string,
	isAdmin bool,
	mustChangePassword bool,
) (string, error) {
	sm.logger.Debug("creating session", "user_type", userType, "username", username)

	id, err := generateSessionID()
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	sess := &db.Session{
		ID:                 id,
		UserType:           userType,
		ProviderID:         providerID,
		Username:           username,
		IsAdmin:            isAdmin,
		MustChangePassword: mustChangePassword,
		IPAddress:          clientIP(r),
		UserAgent:          r.UserAgent(),
		FlashJSON:          "",
		CreatedAt:          now,
		ExpiresAt:          now.Add(sm.ttl),
		LastActivityAt:     now,
	}

	if err := sm.store.CreateSession(r.Context(), sess); err != nil {
		return "", fmt.Errorf("creating session: %w", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sm.cookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   sm.secureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sm.ttl.Seconds()),
	})

	sm.logger.Info("session created",
		slog.String("session_id", id),
		slog.String("username", username),
		slog.String("user_type", userType),
	)

	return id, nil
}

// GetSession reads the session cookie from the request, loads the session from
// the database, and verifies it has not expired. Returns ErrNoSession if the
// cookie is missing, the session is not found, or the session has expired.
func (sm *SessionManager) GetSession(r *http.Request) (*db.Session, error) {
	cookie, err := r.Cookie(sm.cookieName)
	if err != nil {
		return nil, ErrNoSession
	}

	sess, err := sm.store.GetSession(r.Context(), cookie.Value)
	if err != nil {
		return nil, ErrNoSession
	}

	if time.Now().UTC().After(sess.ExpiresAt) {
		// Clean up the expired session from the database.
		_ = sm.store.DeleteSession(r.Context(), sess.ID)
		return nil, ErrNoSession
	}

	return sess, nil
}

// DestroySession deletes the session from the database and clears the cookie.
func (sm *SessionManager) DestroySession(w http.ResponseWriter, r *http.Request) {
	sm.logger.Debug("destroying session")
	cookie, err := r.Cookie(sm.cookieName)
	if err == nil {
		if delErr := sm.store.DeleteSession(r.Context(), cookie.Value); delErr != nil {
			sm.logger.Warn("failed to delete session from store",
				slog.String("session_id", cookie.Value),
				slog.String("error", delErr.Error()),
			)
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sm.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   sm.secureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	sm.logger.Debug("session cookie cleared")
}

// TouchSession updates the session's last_activity_at and slides the expiry
// forward by the configured TTL.
func (sm *SessionManager) TouchSession(ctx context.Context, sessionID string) error {
	newExpiry := time.Now().UTC().Add(sm.ttl)
	return sm.store.TouchSession(ctx, sessionID, newExpiry)
}

// Middleware returns an HTTP middleware that enforces a valid session.
// If no valid session exists the user is redirected to /login.
// Otherwise the session is stored in the request context and the expiry
// is slid forward.
func (sm *SessionManager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := sm.GetSession(r)
		if err != nil {
			sm.logger.Debug("no valid session, redirecting to login", "path", r.URL.Path)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		sm.logger.Debug("session found",
			slog.String("username", sess.Username),
			slog.String("user_type", sess.UserType),
		)

		// Slide expiry.
		if touchErr := sm.TouchSession(r.Context(), sess.ID); touchErr != nil {
			sm.logger.Warn("failed to touch session",
				slog.String("session_id", sess.ID),
				slog.String("error", touchErr.Error()),
			)
		}

		ctx := context.WithValue(r.Context(), contextKey{}, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAdmin returns middleware that checks if the session user is an admin.
// Returns 403 Forbidden if the user is not an admin.
func (sm *SessionManager) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := SessionFromContext(r.Context())
		if sess == nil || !sess.IsAdmin {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireNonResetSession returns middleware that redirects users back to
// /reset-password if they have a password-reset or post-reset flash session.
// This prevents a user mid-flow from navigating to the dashboard or admin pages,
// and prevents a stale flash session (from a just-completed reset) from being
// used to access protected routes with an empty username.
func (sm *SessionManager) RequireNonResetSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := SessionFromContext(r.Context())
		if sess != nil && (sess.UserType == "reset" || sess.UserType == "flash") {
			http.Redirect(w, r, "/reset-password", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequirePasswordChange returns middleware that redirects to /change-password
// if the session's MustChangePassword flag is true.
func (sm *SessionManager) RequirePasswordChange(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := SessionFromContext(r.Context())
		if sess != nil && sess.MustChangePassword {
			http.Redirect(w, r, "/change-password", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireMFA returns middleware that redirects to /mfa if the session has
// a pending MFA verification (MFAPending is true).
func (sm *SessionManager) RequireMFA(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := SessionFromContext(r.Context())
		if sess != nil && sess.MFAPending {
			http.Redirect(w, r, "/mfa", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SessionFromContext extracts the session from the request context.
// Returns nil if no session is present.
func SessionFromContext(ctx context.Context) *db.Session {
	sess, _ := ctx.Value(contextKey{}).(*db.Session)
	return sess
}

// UpdateSessionMustChangePassword updates the must_change_password flag for a session.
func (sm *SessionManager) UpdateSessionMustChangePassword(ctx context.Context, sessionID string, mustChange bool) error {
	return sm.store.UpdateSessionMustChangePassword(ctx, sessionID, mustChange)
}

// StartPurge starts a background goroutine that periodically purges expired
// sessions from the database. It stops when the provided context is cancelled.
func (sm *SessionManager) StartPurge(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				sm.logger.Info("session purge goroutine stopped")
				return
			case <-ticker.C:
				n, err := sm.store.PurgeExpired(ctx)
				if err != nil {
					sm.logger.Error("failed to purge expired sessions",
						slog.String("error", err.Error()),
					)
				} else if n > 0 {
					sm.logger.Info("purged expired sessions",
						slog.Int64("count", n),
					)
				}
			}
		}
	}()
}

// flashData is the internal representation of flash messages stored as JSON.
type flashData struct {
	Category string `json:"category"`
	Message  string `json:"message"`
}

// SetFlash stores a flash message in the session's FlashJSON field.
// Category should be "success" or "error".
func (sm *SessionManager) SetFlash(w http.ResponseWriter, r *http.Request, category, message string) {
	sm.logger.Debug("setting flash", "category", category, "message", message)
	sess := SessionFromContext(r.Context())
	if sess == nil {
		var err error
		sess, err = sm.GetSession(r)
		if err != nil {
			return
		}
	}

	fd := flashData{Category: category, Message: message}
	b, err := json.Marshal(fd)
	if err != nil {
		sm.logger.Error("failed to marshal flash data",
			slog.String("error", err.Error()),
		)
		return
	}

	if err := sm.store.UpdateSessionFlash(r.Context(), sess.ID, string(b)); err != nil {
		sm.logger.Error("failed to set flash",
			slog.String("session_id", sess.ID),
			slog.String("error", err.Error()),
		)
	}
}

// GetFlash reads and clears the flash message from the session.
// Returns a map with "category" and "message" keys, or nil if no flash exists.
func (sm *SessionManager) GetFlash(r *http.Request) map[string]string {
	sess := SessionFromContext(r.Context())
	if sess == nil {
		var err error
		sess, err = sm.GetSession(r)
		if err != nil {
			return nil
		}
	}

	if sess.FlashJSON == "" {
		return nil
	}

	sm.logger.Debug("flash data found", "category", sess.FlashJSON)
	var fd flashData
	if err := json.Unmarshal([]byte(sess.FlashJSON), &fd); err != nil {
		sm.logger.Error("failed to unmarshal flash data",
			slog.String("error", err.Error()),
		)
		return nil
	}

	// Clear the flash after reading.
	if err := sm.store.UpdateSessionFlash(r.Context(), sess.ID, ""); err != nil {
		sm.logger.Error("failed to clear flash",
			slog.String("session_id", sess.ID),
			slog.String("error", err.Error()),
		)
	}
	// Update the in-context copy so repeated calls on this request return nil.
	sess.FlashJSON = ""

	return map[string]string{
		"category": fd.Category,
		"message":  fd.Message,
	}
}
