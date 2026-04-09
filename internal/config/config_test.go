package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()

	if cfg.Server.Addr != ":8080" {
		t.Errorf("expected addr :8080, got %s", cfg.Server.Addr)
	}
	if cfg.Server.DrainTimeout != 15*time.Second {
		t.Errorf("expected drain_timeout 15s, got %s", cfg.Server.DrainTimeout)
	}
	if cfg.Database.Path != "passport.db" {
		t.Errorf("expected db path passport.db, got %s", cfg.Database.Path)
	}
	if cfg.Logging.Stdout.Format != "text" {
		t.Errorf("expected stdout format text, got %s", cfg.Logging.Stdout.Format)
	}
	if cfg.Logging.Stdout.Level != "info" {
		t.Errorf("expected stdout level info, got %s", cfg.Logging.Stdout.Level)
	}
	if cfg.Session.TTL != 8*time.Hour {
		t.Errorf("expected session TTL 8h, got %s", cfg.Session.TTL)
	}
	if cfg.Session.PurgeFreq != 5*time.Minute {
		t.Errorf("expected purge freq 5m, got %s", cfg.Session.PurgeFreq)
	}
	if cfg.Audit.FilePath != "audit.log" {
		t.Errorf("expected audit file_path audit.log, got %s", cfg.Audit.FilePath)
	}
	if cfg.Audit.DBRetention != 720*time.Hour {
		t.Errorf("expected audit db_retention 720h, got %s", cfg.Audit.DBRetention)
	}
	if cfg.Audit.PurgeFreq != 1*time.Hour {
		t.Errorf("expected audit purge_freq 1h, got %s", cfg.Audit.PurgeFreq)
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadValidConfig(t *testing.T) {
	yaml := `
server:
  addr: ":9090"
  drain_timeout: 30s
database:
  path: /tmp/test.db
logging:
  stdout:
    format: json
    level: debug
session:
  ttl: 4h
  purge_freq: 10m
`
	cfg, err := Load(writeTemp(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Addr != ":9090" {
		t.Errorf("expected addr :9090, got %s", cfg.Server.Addr)
	}
	if cfg.Server.DrainTimeout != 30*time.Second {
		t.Errorf("expected drain_timeout 30s, got %s", cfg.Server.DrainTimeout)
	}
	if cfg.Database.Path != "/tmp/test.db" {
		t.Errorf("expected db path /tmp/test.db, got %s", cfg.Database.Path)
	}
	if cfg.Logging.Stdout.Format != "json" {
		t.Errorf("expected stdout format json, got %s", cfg.Logging.Stdout.Format)
	}
	if cfg.Logging.Stdout.Level != "debug" {
		t.Errorf("expected stdout level debug, got %s", cfg.Logging.Stdout.Level)
	}
	if cfg.Session.TTL != 4*time.Hour {
		t.Errorf("expected session TTL 4h, got %s", cfg.Session.TTL)
	}
	if cfg.Session.PurgeFreq != 10*time.Minute {
		t.Errorf("expected purge freq 10m, got %s", cfg.Session.PurgeFreq)
	}
}

func TestLoadPartialConfig(t *testing.T) {
	yaml := `
server:
  addr: ":3000"
`
	cfg, err := Load(writeTemp(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Addr != ":3000" {
		t.Errorf("expected addr :3000, got %s", cfg.Server.Addr)
	}
	// Defaults should be preserved for unset fields
	if cfg.Database.Path != "passport.db" {
		t.Errorf("expected default db path, got %s", cfg.Database.Path)
	}
	if cfg.Logging.Stdout.Format != "text" {
		t.Errorf("expected default stdout format, got %s", cfg.Logging.Stdout.Format)
	}
}

func TestLoadMissingFile(t *testing.T) {
	// Missing file in a non-writable path should still error.
	_, err := Load("/nonexistent/dir/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file in non-writable directory")
	}
}

func TestLoadMissingFileCreatesDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Addr != ":8080" {
		t.Errorf("expected default addr, got %s", cfg.Server.Addr)
	}
	// Verify file was created.
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("expected default config file to be created")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	_, err := Load(writeTemp(t, "{{invalid yaml"))
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "empty addr",
			yaml: "server:\n  addr: \"\"",
		},
		{
			name: "empty db path",
			yaml: "database:\n  path: \"\"",
		},
		{
			name: "invalid log format",
			yaml: "logging:\n  stdout:\n    format: xml",
		},
		{
			name: "invalid log level",
			yaml: "logging:\n  stdout:\n    level: trace",
		},
		{
			name: "negative session TTL",
			yaml: "session:\n  ttl: -1s",
		},
		{
			name: "negative purge freq",
			yaml: "session:\n  purge_freq: -1s",
		},
		{
			name: "tls cert without key",
			yaml: "server:\n  tls_cert: /path/to/cert.pem",
		},
		{
			name: "tls key without cert",
			yaml: "server:\n  tls_key: /path/to/key.pem",
		},
		{
			name: "empty audit file path",
			yaml: "audit:\n  file_path: \"\"",
		},
		{
			name: "negative audit db retention",
			yaml: "audit:\n  db_retention: -1s",
		},
		{
			name: "audit purge freq zero with retention set",
			yaml: "audit:\n  db_retention: 24h\n  purge_freq: 0s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeTemp(t, tt.yaml))
			if err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func TestTLSEnabled(t *testing.T) {
	cfg := Defaults()
	if cfg.TLSEnabled() {
		t.Error("expected TLS disabled by default")
	}

	cfg.Server.TLSCert = "/cert.pem"
	cfg.Server.TLSKey = "/key.pem"
	if !cfg.TLSEnabled() {
		t.Error("expected TLS enabled")
	}
}

func TestLogLevel(t *testing.T) {
	tests := []struct {
		level    string
		expected int
	}{
		{"debug", -4},
		{"info", 0},
		{"warn", 4},
		{"error", 8},
		{"unknown", 0},
	}
	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			cfg := Defaults()
			cfg.Logging.Stdout.Level = tt.level
			if got := cfg.StdoutLogLevel(); got != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, got)
			}
		})
	}
}

func TestSecureCookies(t *testing.T) {
	// TLS configured → secure.
	cfg := Defaults()
	cfg.Server.TLSCert = "/etc/cert.pem"
	cfg.Server.TLSKey = "/etc/key.pem"
	if !cfg.SecureCookies() {
		t.Error("expected SecureCookies true when TLS is configured")
	}

	// TrustProxy set → secure.
	cfg2 := Defaults()
	cfg2.Server.TrustProxy = true
	if !cfg2.SecureCookies() {
		t.Error("expected SecureCookies true when TrustProxy is set")
	}

	// Neither TLS nor proxy → not secure.
	cfg3 := Defaults()
	if cfg3.SecureCookies() {
		t.Error("expected SecureCookies false by default")
	}
}

func TestFileLogLevel(t *testing.T) {
	tests := []struct {
		level    string
		expected int
	}{
		{"debug", -4},
		{"info", 0},
		{"warn", 4},
		{"error", 8},
		{"unknown", 0},
	}
	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			cfg := Defaults()
			cfg.Logging.File.Level = tt.level
			if got := cfg.FileLogLevel(); got != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, got)
			}
		})
	}
}

func TestValidateInvalidStdoutFormat(t *testing.T) {
	cfg := Defaults()
	cfg.Logging.Stdout.Format = "xml"
	if err := cfg.validate(); err == nil {
		t.Error("expected error for invalid stdout format")
	}
}

func TestValidateInvalidStdoutLevel(t *testing.T) {
	cfg := Defaults()
	cfg.Logging.Stdout.Level = "trace"
	if err := cfg.validate(); err == nil {
		t.Error("expected error for invalid stdout level")
	}
}

func TestValidateFileLogInvalidFormat(t *testing.T) {
	cfg := Defaults()
	cfg.Logging.File.Path = "/tmp/passport.log"
	cfg.Logging.File.Format = "bad"
	if err := cfg.validate(); err == nil {
		t.Error("expected error for invalid file log format")
	}
}

func TestValidateFileLogInvalidLevel(t *testing.T) {
	cfg := Defaults()
	cfg.Logging.File.Path = "/tmp/passport.log"
	cfg.Logging.File.Format = "json"
	cfg.Logging.File.Level = "bad"
	if err := cfg.validate(); err == nil {
		t.Error("expected error for invalid file log level")
	}
}

func TestValidateNegativeDBRetention(t *testing.T) {
	cfg := Defaults()
	cfg.Audit.DBRetention = -1
	if err := cfg.validate(); err == nil {
		t.Error("expected error for negative db_retention")
	}
}

func TestValidateTLSMismatch(t *testing.T) {
	cfg := Defaults()
	cfg.Server.TLSCert = "/path/to/cert.pem"
	// TLSKey left empty — should fail validation.
	if err := cfg.validate(); err == nil {
		t.Error("expected error when tls_cert is set without tls_key")
	}
}

func TestLoadCreatesDefaultFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new_config.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Addr != ":8080" {
		t.Errorf("expected default addr :8080, got %s", cfg.Server.Addr)
	}
	if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
		t.Error("expected default config file to be created")
	}
}
