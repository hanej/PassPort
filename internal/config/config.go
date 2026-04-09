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

// Package config handles parsing of the startup configuration file (config.yaml).
// All other configuration is managed through the admin UI and stored in the database.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Logging  LoggingConfig  `yaml:"logging"`
	Session  SessionConfig  `yaml:"session"`
	Audit    AuditConfig    `yaml:"audit"`
}

type ServerConfig struct {
	Addr         string        `yaml:"addr"`
	TLSCert      string        `yaml:"tls_cert"`
	TLSKey       string        `yaml:"tls_key"`
	TrustProxy   bool          `yaml:"trust_proxy"`
	DrainTimeout time.Duration `yaml:"drain_timeout"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type LoggingConfig struct {
	Stdout LogOutputConfig `yaml:"stdout"`
	File   LogFileConfig   `yaml:"file"`
}

type LogOutputConfig struct {
	Format string `yaml:"format"` // "json" or "text"
	Level  string `yaml:"level"`  // "debug", "info", "warn", "error"
}

type LogFileConfig struct {
	Path   string `yaml:"path"`   // empty = no file logging
	Format string `yaml:"format"` // "json" or "text"
	Level  string `yaml:"level"`  // "debug", "info", "warn", "error"
}

type SessionConfig struct {
	TTL       time.Duration `yaml:"ttl"`
	PurgeFreq time.Duration `yaml:"purge_freq"`
}

type AuditConfig struct {
	// FilePath is the path to the append-only JSON audit log file.
	FilePath string `yaml:"file_path"`

	// DBRetention controls how long audit entries are kept in the database.
	// Entries older than this are automatically purged. Set to 0 to disable purging.
	DBRetention time.Duration `yaml:"db_retention"`

	// PurgeFreq controls how often the database purge runs.
	PurgeFreq time.Duration `yaml:"purge_freq"`
}

func Defaults() Config {
	return Config{
		Server: ServerConfig{
			Addr:         ":8080",
			DrainTimeout: 15 * time.Second,
		},
		Database: DatabaseConfig{
			Path: "passport.db",
		},
		Logging: LoggingConfig{
			Stdout: LogOutputConfig{
				Format: "text",
				Level:  "info",
			},
			File: LogFileConfig{
				Path:   "",
				Format: "json",
				Level:  "debug",
			},
		},
		Session: SessionConfig{
			TTL:       8 * time.Hour,
			PurgeFreq: 5 * time.Minute,
		},
		Audit: AuditConfig{
			FilePath:    "audit.log",
			DBRetention: 720 * time.Hour, // 30 days
			PurgeFreq:   1 * time.Hour,
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Create a default config file.
			if writeErr := writeDefaultConfig(path); writeErr != nil {
				return nil, fmt.Errorf("creating default config file: %w", writeErr)
			}
			fmt.Fprintf(os.Stderr, "Created default config file: %s\n", path)
			return &cfg, nil
		}
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

func writeDefaultConfig(path string) error {
	content := defaultConfigYAML()
	return os.WriteFile(path, []byte(content), 0644)
}

func defaultConfigYAML() string {
	return `# PassPort — Self-Service Password Management
# Startup configuration. All other settings are managed via the Admin UI.

server:
  # Address to listen on (e.g., ":8080", "0.0.0.0:8443")
  addr: ":8080"

  # TLS certificate and key paths (optional; omit for plain HTTP)
  # tls_cert: /etc/passport/tls/cert.pem
  # tls_key: /etc/passport/tls/key.pem

  # Set to true if running behind a reverse proxy that terminates TLS.
  # This trusts X-Forwarded-Proto to determine if the connection is secure,
  # and sets the Secure flag on cookies accordingly.
  trust_proxy: false

  # Time to wait for in-flight requests to complete on shutdown
  drain_timeout: 15s

database:
  # Path to SQLite database file
  path: passport.db

logging:
  # Stdout logging
  stdout:
    format: text    # "json" or "text"
    level: info     # "debug", "info", "warn", "error"

  # File logging (optional — leave path empty to disable)
  file:
    path: ""        # e.g., "passport.log"
    format: json    # "json" or "text"
    level: debug    # "debug", "info", "warn", "error"

session:
  # Session time-to-live
  ttl: 8h

  # How often to purge expired sessions
  purge_freq: 5m

audit:
  # Path to the append-only JSON audit log file (permanent record)
  file_path: audit.log

  # How long to keep audit entries in the database (for the admin UI viewer).
  # Entries older than this are automatically purged from the DB.
  # The file log is never purged. Set to 0 to disable DB purging.
  db_retention: 720h  # 30 days

  # How often the DB audit purge runs
  purge_freq: 1h
`
}

func (c *Config) validate() error {
	if c.Server.Addr == "" {
		return fmt.Errorf("server.addr is required")
	}

	if c.Database.Path == "" {
		return fmt.Errorf("database.path is required")
	}

	switch c.Logging.Stdout.Format {
	case "json", "text":
	default:
		return fmt.Errorf("logging.stdout.format must be \"json\" or \"text\", got %q", c.Logging.Stdout.Format)
	}

	switch c.Logging.Stdout.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("logging.stdout.level must be one of debug/info/warn/error, got %q", c.Logging.Stdout.Level)
	}

	if c.Logging.File.Path != "" {
		switch c.Logging.File.Format {
		case "json", "text":
		default:
			return fmt.Errorf("logging.file.format must be \"json\" or \"text\", got %q", c.Logging.File.Format)
		}
		switch c.Logging.File.Level {
		case "debug", "info", "warn", "error":
		default:
			return fmt.Errorf("logging.file.level must be one of debug/info/warn/error, got %q", c.Logging.File.Level)
		}
	}

	if c.Session.TTL <= 0 {
		return fmt.Errorf("session.ttl must be positive")
	}

	if c.Session.PurgeFreq <= 0 {
		return fmt.Errorf("session.purge_freq must be positive")
	}

	if (c.Server.TLSCert == "") != (c.Server.TLSKey == "") {
		return fmt.Errorf("both server.tls_cert and server.tls_key must be set together")
	}

	if c.Audit.FilePath == "" {
		return fmt.Errorf("audit.file_path is required")
	}

	if c.Audit.DBRetention < 0 {
		return fmt.Errorf("audit.db_retention must be non-negative")
	}

	if c.Audit.DBRetention > 0 && c.Audit.PurgeFreq <= 0 {
		return fmt.Errorf("audit.purge_freq must be positive when db_retention is set")
	}

	return nil
}

// TLSEnabled returns true if TLS cert and key are configured.
func (c *Config) TLSEnabled() bool {
	return c.Server.TLSCert != "" && c.Server.TLSKey != ""
}

// SecureCookies returns true if cookies should have the Secure flag set.
// This is true when TLS is enabled directly or when behind a trusted proxy.
func (c *Config) SecureCookies() bool {
	return c.TLSEnabled() || c.Server.TrustProxy
}

// StdoutLogLevel returns the slog.Level for stdout logging.
func (c *Config) StdoutLogLevel() int {
	return parseLogLevel(c.Logging.Stdout.Level)
}

// FileLogLevel returns the slog.Level for file logging.
func (c *Config) FileLogLevel() int {
	return parseLogLevel(c.Logging.File.Level)
}

func parseLogLevel(level string) int {
	switch level {
	case "debug":
		return -4 // slog.LevelDebug
	case "warn":
		return 4 // slog.LevelWarn
	case "error":
		return 8 // slog.LevelError
	default:
		return 0 // slog.LevelInfo
	}
}
