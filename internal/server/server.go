// Package server provides an HTTP server with graceful shutdown support.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Server wraps an http.Server with structured logging and graceful shutdown.
type Server struct {
	httpServer *http.Server
	logger     *slog.Logger
}

// New creates a Server with sensible timeouts for the given address and handler.
func New(addr string, handler http.Handler, logger *slog.Logger) *Server {
	return &Server{
		httpServer: &http.Server{
			Addr:         addr,
			Handler:      handler,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
		logger: logger,
	}
}

// Start begins listening on the configured address. It returns nil if the
// server was closed via Shutdown; all other errors are returned.
func (s *Server) Start() error {
	s.logger.Info("server starting", "addr", s.httpServer.Addr)
	if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// StartTLS begins listening with TLS on the configured address.
func (s *Server) StartTLS(certFile, keyFile string) error {
	s.logger.Info("server starting with TLS", "addr", s.httpServer.Addr)
	if err := s.httpServer.ListenAndServeTLS(certFile, keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown gracefully drains in-flight requests within the given context deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("server shutting down")
	return s.httpServer.Shutdown(ctx)
}

// GracefulShutdown blocks until SIGINT or SIGTERM is received, then shuts the
// server down allowing up to drainTimeout for in-flight requests to complete.
func (s *Server) GracefulShutdown(drainTimeout time.Duration) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	sig := <-quit
	s.logger.Info("received shutdown signal", "signal", sig.String())

	ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()

	if err := s.Shutdown(ctx); err != nil {
		s.logger.Error("server forced to shutdown", "error", err)
	} else {
		s.logger.Info("server stopped gracefully")
	}
}
