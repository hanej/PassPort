//go:build windows

package main

import (
	"log/slog"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/logging"
)

// listenForSIGHUP is a no-op on Windows since SIGHUP doesn't exist.
// On Windows, use the scheduled task approach to restart the service for log rotation.
func listenForSIGHUP(_ *logging.RotatableFile, _ *audit.Logger, _ *slog.Logger) {}
