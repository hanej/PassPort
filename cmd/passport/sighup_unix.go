//go:build !windows

package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/logging"
)

// listenForSIGHUP starts a goroutine that reopens all log files on SIGHUP.
// This enables log rotation with tools like logrotate and newsyslog.
func listenForSIGHUP(logFile *logging.RotatableFile, auditLogger *audit.Logger, logger *slog.Logger) {
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)

	go func() {
		for range sighup {
			logger.Info("received SIGHUP, reopening log files")

			if logFile != nil {
				if err := logFile.Reopen(); err != nil {
					logger.Error("failed to reopen application log file", "error", err)
				} else {
					logger.Info("application log file reopened")
				}
			}

			if auditLogger != nil {
				if err := auditLogger.ReopenFile(); err != nil {
					logger.Error("failed to reopen audit log file", "error", err)
				} else {
					logger.Info("audit log file reopened")
				}
			}
		}
	}()
}
