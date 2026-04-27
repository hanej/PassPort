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

package handler

import (
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	csrf "filippo.io/csrf/gorilla"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/ratelimit"
	"github.com/hanej/passport/web"
)

// RouterConfig holds all dependencies needed to build the HTTP router.
type RouterConfig struct {
	Health              *HealthHandler
	Login               *LoginHandler
	ForgotPassword      *ForgotPasswordHandler
	Dashboard           *DashboardHandler
	Link                *LinkHandler
	Bootstrap           *BootstrapHandler
	AdminIDP            *AdminIDPHandler
	AdminSMTP           *AdminSMTPHandler
	AdminGroups         *AdminGroupsHandler
	AdminMappings       *AdminMappingsHandler
	AdminAudit          *AdminAuditHandler
	AdminMFA            *AdminMFAHandler
	AdminEmailTemplates *AdminEmailTemplatesHandler
	AdminExpiration     *AdminExpirationHandler
	AdminBranding       *AdminBrandingHandler
	AdminMigrate        *AdminMigrateHandler
	AdminDocs           *AdminDocsHandler
	AdminReports        *AdminReportsHandler
	MFA                 *MFAHandler
	ADChangePassword    *ADChangePasswordHandler
	Sessions            *auth.SessionManager
	Store               db.Store
	CSRFKey             []byte
	SecureCookie        bool
	LoginLimiter        *ratelimit.Limiter
	LinkLimiter         *ratelimit.Limiter
	UploadsDir          string
	Logger              *slog.Logger
}

// NewRouter builds the application HTTP router with all routes and middleware.
func NewRouter(cfg RouterConfig) http.Handler {
	r := chi.NewRouter()

	// Global middleware (applied to all routes)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(requestLogger(cfg.Logger))

	// Static assets — served before CSRF middleware, no protection needed
	staticFS, _ := fs.Sub(web.Assets, "static")
	fileServer := http.StripPrefix("/static", http.FileServer(http.FS(staticFS)))
	r.Get("/static/*", func(w http.ResponseWriter, r *http.Request) {
		fileServer.ServeHTTP(w, r)
	})

	// Uploaded files (logos, etc.) — served before CSRF middleware
	if cfg.UploadsDir != "" {
		uploadsServer := http.StripPrefix("/uploads", http.FileServer(http.Dir(cfg.UploadsDir)))
		r.Get("/uploads/*", func(w http.ResponseWriter, r *http.Request) {
			uploadsServer.ServeHTTP(w, r)
		})
	}

	// Health endpoints — no CSRF, no auth
	r.Get("/healthz", cfg.Health.Liveness)
	r.Get("/readyz", cfg.Health.Readiness)

	// All remaining routes use CSRF protection.
	csrfMiddleware := csrf.Protect(cfg.CSRFKey)

	r.Group(func(r chi.Router) {
		r.Use(csrfMiddleware)

		// Public routes
		r.Group(func(r chi.Router) {
			if cfg.LoginLimiter != nil {
				r.Use(ratelimit.Middleware(cfg.LoginLimiter, ratelimit.KeyByIP))
			}
			r.Get("/login", cfg.Login.ShowLogin)
			r.Post("/login", cfg.Login.Login)
		})

		// Forgot-password routes (public, no auth required).
		r.Group(func(r chi.Router) {
			if cfg.LoginLimiter != nil {
				r.Use(ratelimit.Middleware(cfg.LoginLimiter, ratelimit.KeyByIP))
			}
			r.Get("/forgot-password", cfg.ForgotPassword.ShowForm)
			r.Post("/forgot-password", cfg.ForgotPassword.Submit)
		})

		r.Get("/logout", cfg.Login.Logout)

		// Public IDP status endpoint (used by login page before auth).
		// Returns only online/offline — no error details exposed.
		r.Get("/idp-status/{id}", cfg.Dashboard.PublicIDPStatus)

		// Root redirect
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/login", http.StatusFound)
		})

		// Authenticated routes
		r.Group(func(r chi.Router) {
			r.Use(cfg.Sessions.Middleware)

			// MFA flow — must remain outside RequireMFA so users with
			// MFAPending can reach the verification pages.
			r.Get("/mfa", cfg.MFA.ShowMFA)
			r.Get("/mfa/callback", cfg.MFA.Callback)
			r.Post("/mfa/verify-otp", cfg.MFA.VerifyOTP)
			r.Post("/mfa/resend-otp", cfg.MFA.ResendOTP)

			// Everything else requires MFA to be completed (if pending).
			r.Group(func(r chi.Router) {
				r.Use(cfg.Sessions.RequireMFA)

				// Password reset (forgot-password flow, requires reset session)
				r.Get("/reset-password", cfg.ForgotPassword.ShowReset)
				r.Post("/reset-password", cfg.ForgotPassword.ResetPassword)

				// Force password change page (local admin)
				r.Get("/change-password", cfg.Bootstrap.ShowChangePassword)
				r.Post("/change-password", cfg.Bootstrap.ChangePassword)

				// Force password change page (AD users)
				r.Get("/ad-change-password", cfg.ADChangePassword.ShowChangePassword)
				r.Post("/ad-change-password", cfg.ADChangePassword.ChangePassword)

				// All other authenticated routes redirect to /change-password
				// if the session has must_change_password set, and redirect to
				// /reset-password if the session is a forgot-password reset session.
				r.Group(func(r chi.Router) {
					r.Use(cfg.Sessions.RequirePasswordChange)
					r.Use(cfg.Sessions.RequireNonResetSession)

					// User dashboard
					r.Get("/dashboard", cfg.Dashboard.ShowDashboard)
					r.Post("/dashboard/change-password", cfg.Dashboard.ChangePassword)
					r.Get("/dashboard/idp-status/{id}", cfg.Dashboard.IDPStatus)

					// Manual IDP linking with rate limiting
					r.Group(func(r chi.Router) {
						if cfg.LinkLimiter != nil {
							r.Use(ratelimit.Middleware(cfg.LinkLimiter, ratelimit.KeyByIP))
						}
						r.Post("/dashboard/link-account", cfg.Link.LinkAccount)
					})

					// Admin routes
					r.Route("/admin", func(r chi.Router) {
						r.Use(cfg.Sessions.RequireAdmin)

						r.Get("/", func(w http.ResponseWriter, req *http.Request) {
							http.Redirect(w, req, "/admin/idp", http.StatusFound)
						})

						// IDP management
						r.Get("/idp", cfg.AdminIDP.List)
						r.Get("/idp/new", cfg.AdminIDP.ShowCreate)
						r.Post("/idp", cfg.AdminIDP.Create)
						r.Post("/idp/test-connection", cfg.AdminIDP.TestConnectionFromForm)
						r.Get("/idp/{id}/browse", cfg.AdminIDP.BrowseChildren)
						r.Get("/idp/{id}/search", cfg.AdminIDP.SearchDirectory)
						r.Get("/idp/{id}/entry", cfg.AdminIDP.ReadEntry)
						r.Get("/idp/{id}/browse-page", cfg.AdminIDP.BrowsePage)
						r.Get("/idp/{id}/edit", cfg.AdminIDP.ShowEdit)
						r.Post("/idp/{id}", cfg.AdminIDP.Update)
						r.Post("/idp/{id}/logo", cfg.AdminIDP.UploadLogo)
						r.Post("/idp/{id}/delete", cfg.AdminIDP.Delete)
						r.Post("/idp/{id}/test", cfg.AdminIDP.TestConnection)
						r.Post("/idp/{id}/toggle", cfg.AdminIDP.Toggle)
						r.Get("/idp/{id}/expiration", cfg.AdminExpiration.Show)
						r.Post("/idp/{id}/expiration", cfg.AdminExpiration.Save)
						r.Post("/idp/{id}/expiration/run", cfg.AdminExpiration.RunNow)
						r.Post("/idp/{id}/expiration/dry-run", cfg.AdminExpiration.DryRun)

						// SMTP
						r.Get("/smtp", cfg.AdminSMTP.Show)
						r.Post("/smtp", cfg.AdminSMTP.Save)
						r.Post("/smtp/test", cfg.AdminSMTP.TestEmail)

						// Email templates
						r.Get("/email-templates", cfg.AdminEmailTemplates.List)
						r.Post("/email-templates/preview", cfg.AdminEmailTemplates.Preview)
						r.Get("/email-templates/{type}/edit", cfg.AdminEmailTemplates.Edit)
						r.Post("/email-templates/{type}", cfg.AdminEmailTemplates.Save)
						r.Post("/email-templates/{type}/delete", cfg.AdminEmailTemplates.Delete)
						r.Post("/email-templates/{type}/reset", cfg.AdminEmailTemplates.ResetDefault)

						// MFA management
						r.Get("/mfa", cfg.AdminMFA.List)
						r.Get("/mfa/new", cfg.AdminMFA.ShowCreate)
						r.Post("/mfa", cfg.AdminMFA.Create)
						r.Post("/mfa/default", cfg.AdminMFA.SetDefault)
						r.Post("/mfa/login-toggle", cfg.AdminMFA.ToggleMFALogin)
						r.Get("/mfa/{id}/edit", cfg.AdminMFA.ShowEdit)
						r.Post("/mfa/{id}", cfg.AdminMFA.Update)
						r.Post("/mfa/{id}/delete", cfg.AdminMFA.Delete)
						r.Post("/mfa/{id}/toggle", cfg.AdminMFA.Toggle)
						r.Post("/mfa/{id}/test", cfg.AdminMFA.TestConnection)

						// Admin groups
						r.Get("/groups", cfg.AdminGroups.List)
						r.Post("/groups", cfg.AdminGroups.Create)
						r.Get("/groups/{id}/members", cfg.AdminGroups.Members)
						r.Post("/groups/{id}/delete", cfg.AdminGroups.Delete)

						// User mappings
						r.Get("/mappings", cfg.AdminMappings.Show)
						r.Get("/mappings/search", cfg.AdminMappings.Search)
						r.Post("/mappings/{id}/delete", cfg.AdminMappings.Delete)
						r.Post("/mappings/delete-all", cfg.AdminMappings.DeleteAll)

						// Audit log
						r.Get("/audit", cfg.AdminAudit.List)

						// Branding
						r.Get("/branding", cfg.AdminBranding.Show)
						r.Post("/branding", cfg.AdminBranding.Save)

						// Import/Export
						r.Get("/migrate", cfg.AdminMigrate.Show)
						r.Get("/migrate/export", cfg.AdminMigrate.Export)
						r.Post("/migrate/import", cfg.AdminMigrate.Import)

						// Documentation
						r.Get("/docs", cfg.AdminDocs.Show)

						// Reports
						r.Get("/reports", cfg.AdminReports.List)
						r.Get("/reports/{id}/{type}", cfg.AdminReports.Show)
						r.Post("/reports/{id}/{type}", cfg.AdminReports.Save)
						r.Post("/reports/{id}/{type}/send", cfg.AdminReports.SendNow)
						r.Post("/reports/{id}/{type}/preview", cfg.AdminReports.Preview)
					})
				})
			})
		})
	})

	return r
}

// requestLogger returns middleware that logs each request with its client IP,
// method, path, status code, and duration. The RealIP middleware must run
// before this so that r.RemoteAddr reflects X-Forwarded-For when present.
func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(ww, r)

			logger.Info("http request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.Status(),
				"duration_ms", time.Since(start).Milliseconds(),
				"ip", r.RemoteAddr,
				"request_id", middleware.GetReqID(r.Context()),
			)
		})
	}
}
