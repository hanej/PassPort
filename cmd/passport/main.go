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

package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/hanej/passport/docs"
	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/config"
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/handler"
	"github.com/hanej/passport/internal/idp"
	"github.com/hanej/passport/internal/idp/correlation"
	"github.com/hanej/passport/internal/job"
	"github.com/hanej/passport/internal/logging"
	"github.com/hanej/passport/internal/migrate"
	"github.com/hanej/passport/internal/ratelimit"
	"github.com/hanej/passport/internal/server"
)

// fanoutHandler is a slog.Handler that writes log records to multiple handlers.
type fanoutHandler struct {
	handlers []slog.Handler
}

func (f fanoutHandler) Enabled(_ context.Context, level slog.Level) bool {
	for _, h := range f.handlers {
		if h.Enabled(context.Background(), level) {
			return true
		}
	}
	return false
}

func (f fanoutHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range f.handlers {
		if h.Enabled(ctx, r.Level) {
			if err := h.Handle(ctx, r.Clone()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (f fanoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	hs := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		hs[i] = h.WithAttrs(attrs)
	}
	return fanoutHandler{handlers: hs}
}

func (f fanoutHandler) WithGroup(name string) slog.Handler {
	hs := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		hs[i] = h.WithGroup(name)
	}
	return fanoutHandler{handlers: hs}
}

// correlatorAdapter adapts the correlation.Engine (which returns []MappingResult, error)
// to the handler.CorrelatorInterface (which returns only error).
type correlatorAdapter struct {
	engine *correlation.Engine
}

func (a *correlatorAdapter) CorrelateUser(ctx context.Context, authProviderID, authUsername string) error {
	_, err := a.engine.CorrelateUser(ctx, authProviderID, authUsername)
	return err
}

// deriveKey produces a deterministic 32-byte key from a master key and a context label
// using HMAC-SHA256. This ensures derived keys are stable across restarts.
func deriveKey(masterKey, label []byte) []byte {
	h := hmac.New(sha256.New, masterKey)
	h.Write(label)
	return h.Sum(nil)
}

func main() {
	configPath := flag.String("config", "config.yaml", "path to configuration file")
	exportPath := flag.String("export", "", "export configuration to file and exit (secrets decrypted)")
	backupPath := flag.String("backup", "", "backup configuration to file and exit (secrets stay encrypted)")
	importPath := flag.String("import", "", "import configuration from file and exit")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Set up structured logging — stdout + optional file with independent levels/formats.
	var handlers []slog.Handler

	// Stdout handler.
	stdoutOpts := &slog.HandlerOptions{Level: slog.Level(cfg.StdoutLogLevel())}
	if cfg.Logging.Stdout.Format == "json" {
		handlers = append(handlers, slog.NewJSONHandler(os.Stdout, stdoutOpts))
	} else {
		handlers = append(handlers, slog.NewTextHandler(os.Stdout, stdoutOpts))
	}

	// File handler (optional) — uses RotatableFile so SIGHUP can reopen after rotation.
	var logFile *logging.RotatableFile
	if cfg.Logging.File.Path != "" {
		var err error
		logFile, err = logging.NewRotatableFile(cfg.Logging.File.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open log file %s: %v\n", cfg.Logging.File.Path, err)
			os.Exit(1)
		}
		defer func() { _ = logFile.Close() }()

		fileOpts := &slog.HandlerOptions{Level: slog.Level(cfg.FileLogLevel())}
		if cfg.Logging.File.Format == "json" {
			handlers = append(handlers, slog.NewJSONHandler(logFile, fileOpts))
		} else {
			handlers = append(handlers, slog.NewTextHandler(logFile, fileOpts))
		}
	}

	// Fan-out handler that writes to all configured outputs.
	logger := slog.New(fanoutHandler{handlers: handlers})
	slog.SetDefault(logger)

	logger.Info("PassPort starting",
		"addr", cfg.Server.Addr,
		"tls", cfg.TLSEnabled(),
		"trust_proxy", cfg.Server.TrustProxy,
		"secure_cookies", cfg.SecureCookies(),
		"db", cfg.Database.Path,
	)

	// Initialize master key and crypto service
	masterKey, err := crypto.LoadMasterKey()
	if err != nil {
		logger.Error("failed to load master key", "error", err)
		os.Exit(1)
	}
	cryptoSvc, err := crypto.NewService(masterKey, 1)
	if err != nil {
		logger.Error("failed to create crypto service", "error", err)
		os.Exit(1)
	}
	logger.Info("master key loaded")

	// Open database
	database, err := db.Open(cfg.Database.Path)
	if err != nil {
		logger.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer func() { _ = database.Close() }()

	// Run migrations
	ctx := context.Background()
	if err := database.Migrate(ctx); err != nil {
		logger.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}
	logger.Info("database migrations applied")

	// Handle CLI export/backup/import modes — these exit without starting the server.
	if *exportPath != "" {
		data, err := migrate.BuildExport(ctx, database, cryptoSvc)
		if err != nil {
			logger.Error("export failed", "error", err)
			os.Exit(1)
		}
		jsonBytes, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			logger.Error("failed to marshal export JSON", "error", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*exportPath, jsonBytes, 0600); err != nil {
			logger.Error("failed to write export file", "error", err, "path", *exportPath)
			os.Exit(1)
		}
		logger.Info("configuration exported", "path", *exportPath)
		os.Exit(0)
	}
	if *backupPath != "" {
		data, err := migrate.BuildBackup(ctx, database)
		if err != nil {
			logger.Error("backup failed", "error", err)
			os.Exit(1)
		}
		jsonBytes, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			logger.Error("failed to marshal backup JSON", "error", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*backupPath, jsonBytes, 0600); err != nil {
			logger.Error("failed to write backup file", "error", err, "path", *backupPath)
			os.Exit(1)
		}
		logger.Info("configuration backed up", "path", *backupPath)
		os.Exit(0)
	}
	if *importPath != "" {
		fileBytes, err := os.ReadFile(*importPath)
		if err != nil {
			logger.Error("failed to read import file", "error", err, "path", *importPath)
			os.Exit(1)
		}
		var data migrate.ExportData
		if err := json.Unmarshal(fileBytes, &data); err != nil {
			logger.Error("failed to parse import file", "error", err)
			os.Exit(1)
		}
		result, err := migrate.RunImport(ctx, database, cryptoSvc, &data, migrate.AllSections())
		if err != nil {
			logger.Error("import failed", "error", err)
			os.Exit(1)
		}
		logger.Info("configuration imported",
			"admins", result.LocalAdmins,
			"idps", result.IDPs,
			"groups", result.AdminGroups,
			"mappings", result.UserMappings,
			"smtp", result.SMTP,
			"mfa", result.MFAProviders,
			"branding", result.Branding,
			"templates", result.EmailTemplates,
			"errors", len(result.Errors),
		)
		if len(result.Errors) > 0 {
			for _, e := range result.Errors {
				logger.Warn("import error", "detail", e)
			}
		}
		os.Exit(0)
	}

	// Bootstrap local admin
	generatedPassword, err := auth.Bootstrap(ctx, database, logger)
	if err != nil {
		logger.Error("failed to bootstrap local admin", "error", err)
		os.Exit(1)
	}
	if generatedPassword != "" {
		logger.Info("========================================")
		logger.Info("LOCAL ADMIN ACCOUNT CREATED")
		logger.Info("Username: admin")
		logger.Info("Password: " + generatedPassword)
		logger.Info("This password will NOT be shown again.")
		logger.Info("You will be required to change it on first login.")
		logger.Info("========================================")
	}

	// Initialize audit logger (DB + file)
	auditLogger, err := audit.NewLogger(database, cfg.Audit.FilePath, logger)
	if err != nil {
		logger.Error("failed to create audit logger", "error", err)
		os.Exit(1)
	}
	defer func() { _ = auditLogger.Close() }()

	// Start audit DB purge background goroutine
	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel()
	auditLogger.StartDBPurge(appCtx, cfg.Audit.DBRetention, cfg.Audit.PurgeFreq)

	// Initialize session manager
	sessions := auth.NewSessionManager(database, cfg.Session.TTL, cfg.SecureCookies(), logger)
	sessions.StartPurge(appCtx, cfg.Session.PurgeFreq)

	// Initialize IDP registry and correlation engine
	registry := idp.NewRegistry(logger)
	correlationEngine := correlation.New(database, registry, logger)
	correlator := &correlatorAdapter{engine: correlationEngine}

	// Initialize template renderer
	renderer, err := handler.NewRenderer(logger)
	if err != nil {
		logger.Error("failed to create renderer", "error", err)
		os.Exit(1)
	}

	// Initialize rate limiters
	loginLimiter := ratelimit.NewLimiter(1, 10, logger) // 1 req/s, burst 10
	linkLimiter := ratelimit.NewLimiter(0.5, 5, logger) // 0.5 req/s, burst 5
	loginLimiter.StartCleanup(appCtx, 10*time.Minute)
	linkLimiter.StartCleanup(appCtx, 10*time.Minute)

	// Derive CSRF key from master key so it's stable across restarts.
	// This prevents CSRF token invalidation when the server restarts.
	csrfKey := deriveKey(masterKey, []byte("sspr-csrf-key-v1"))

	// Initialize handlers
	healthHandler := handler.NewHealthHandler(database, logger)
	loginHandler := handler.NewLoginHandler(database, sessions, registry, correlator, cryptoSvc, renderer, auditLogger, logger)
	dashboardHandler := handler.NewDashboardHandler(database, sessions, registry, correlator, renderer, auditLogger, logger)
	linkHandler := handler.NewLinkHandler(database, sessions, registry, renderer, auditLogger, logger)
	bootstrapHandler := handler.NewBootstrapHandler(database, sessions, renderer, auditLogger, logger)
	uploadsDir := filepath.Join(filepath.Dir(cfg.Database.Path), "uploads")
	adminIDPHandler := handler.NewAdminIDPHandler(database, cryptoSvc, registry, renderer, auditLogger, logger, uploadsDir)
	// Load all enabled IDPs into the live registry.
	if err := adminIDPHandler.LoadProviders(context.Background()); err != nil {
		logger.Error("failed to load providers at startup", "error", err)
	}

	expirationNotifier := job.New(database, registry, cryptoSvc, auditLogger, logger)
	expirationNotifier.Start(appCtx)

	reportScheduler := job.NewReportScheduler(database, registry, cryptoSvc, auditLogger, logger)
	reportScheduler.Start(appCtx)

	adminExpirationHandler := handler.NewAdminExpirationHandler(database, expirationNotifier, renderer, auditLogger, logger)

	adminMFAHandler := handler.NewAdminMFAHandler(database, cryptoSvc, renderer, auditLogger, logger)
	mfaHandler := handler.NewMFAHandler(database, sessions, cryptoSvc, registry, renderer, auditLogger, logger)
	forgotPasswordHandler := handler.NewForgotPasswordHandler(database, registry, sessions, renderer, auditLogger, logger)

	adminSMTPHandler := handler.NewAdminSMTPHandler(database, cryptoSvc, renderer, auditLogger, logger)
	adminEmailTemplatesHandler := handler.NewAdminEmailTemplatesHandler(database, renderer, sessions, auditLogger, logger)
	adminGroupsHandler := handler.NewAdminGroupsHandler(database, registry, renderer, auditLogger, logger)
	adminMappingsHandler := handler.NewAdminMappingsHandler(database, registry, renderer, auditLogger, logger)
	adminAuditHandler := handler.NewAdminAuditHandler(database, renderer, logger)
	adminBrandingHandler := handler.NewAdminBrandingHandler(database, renderer, auditLogger, logger, uploadsDir)
	adminMigrateHandler := handler.NewAdminMigrateHandler(database, cryptoSvc, renderer, auditLogger, logger)
	adminDocsHandler := handler.NewAdminDocsHandler(renderer, logger, docs.GuideMarkdown)
	adminReportsHandler := handler.NewAdminReportsHandler(database, reportScheduler, renderer, auditLogger, logger)

	// Load branding from DB and set it on the renderer so templates use the saved config.
	brandingCfg, err := database.GetBrandingConfig(ctx)
	if err != nil {
		logger.Error("failed to load branding config", "error", err)
		os.Exit(1)
	}
	renderer.SetBranding(brandingCfg)

	// Build router
	router := handler.NewRouter(handler.RouterConfig{
		Health:              healthHandler,
		Login:               loginHandler,
		ForgotPassword:      forgotPasswordHandler,
		Dashboard:           dashboardHandler,
		Link:                linkHandler,
		Bootstrap:           bootstrapHandler,
		AdminIDP:            adminIDPHandler,
		AdminSMTP:           adminSMTPHandler,
		AdminEmailTemplates: adminEmailTemplatesHandler,
		AdminGroups:         adminGroupsHandler,
		AdminMappings:       adminMappingsHandler,
		AdminAudit:          adminAuditHandler,
		AdminBranding:       adminBrandingHandler,
		AdminMigrate:        adminMigrateHandler,
		AdminDocs:           adminDocsHandler,
		AdminReports:        adminReportsHandler,
		AdminMFA:            adminMFAHandler,
		AdminExpiration:     adminExpirationHandler,
		MFA:                 mfaHandler,
		Sessions:            sessions,
		CSRFKey:             csrfKey,
		SecureCookie:        cfg.SecureCookies(),
		LoginLimiter:        loginLimiter,
		LinkLimiter:         linkLimiter,
		UploadsDir:          uploadsDir,
		Logger:              logger,
	})

	// Listen for SIGHUP to reopen all log files after rotation.
	listenForSIGHUP(logFile, auditLogger, logger)

	// Start server
	srv := server.New(cfg.Server.Addr, router, logger)

	// Start graceful shutdown listener
	go srv.GracefulShutdown(cfg.Server.DrainTimeout)

	if cfg.TLSEnabled() {
		logger.Info("starting HTTPS server", "addr", cfg.Server.Addr)
		if err := srv.StartTLS(cfg.Server.TLSCert, cfg.Server.TLSKey); err != nil {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	} else {
		logger.Info("starting HTTP server", "addr", cfg.Server.Addr)
		if err := srv.Start(); err != nil {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}

	logger.Info("PassPort shutdown complete")
}
