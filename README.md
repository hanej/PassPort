# PassPort

**Self-service password management for Active Directory and FreeIPA.**

[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](#tech-stack)
[![SQLite](https://img.shields.io/badge/SQLite-embedded-003B57?logo=sqlite&logoColor=white)](#tech-stack)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

PassPort is a single-binary Go web application that lets end users change and reset their passwords across multiple LDAP directories from one unified dashboard. Admins configure everything through the built-in web UI -- no external databases, no config files for runtime settings.

<!-- ![PassPort Dashboard](docs/screenshot.png) -->

---

## Features

- **Multi-directory support** -- Active Directory and FreeIPA via LDAP/LDAPS/STARTTLS
- **Unified dashboard** -- users see all linked directory accounts in one place
- **Forgot-password flow** -- self-service reset with optional Duo MFA verification
- **Password expiration notifications** -- cron-scheduled emails with per-IDP templates
- **Automatic account correlation** -- links user accounts across IDPs using configurable attribute rules
- **LDAP directory browser** -- browse and search directory trees from the admin UI
- **Whitelabel branding** -- custom title, logo, subtitle, footer text, per-IDP logos
- **Rich email templates** -- TinyMCE editor with preview, per-IDP overrides, template variables
- **Audit logging** -- dual output to append-only JSON file and database with retention controls
- **Admin groups** -- map LDAP groups to the admin role
- **Backup & migration** -- CLI export/import with encrypted or plaintext secrets, web UI with section selection
- **Single binary** -- embedded SQLite, embedded static assets, zero external dependencies at runtime
- **Security hardened** -- AES-256-GCM encryption, CSRF protection, rate limiting, secure cookies, systemd hardening

## Quick Start

### Prerequisites

- Go 1.26+
- OpenSSL (for master key generation)

> **Note:** PassPort has only been tested on Linux. While the project is designed to be cross-platform (builds available for macOS and Windows), production deployment is only supported on Linux systems.

### Build

```bash
make build
```

This produces `bin/passport`. Cross-compile for Linux/Windows/ARM64 with `make build-all`.

### Generate a Master Key

PassPort encrypts all secrets (LDAP service account passwords, SMTP credentials, MFA secrets) at rest using AES-256-GCM. A 32-byte master key is required.

```bash
# Option A: File-based key (recommended for production)
sudo mkdir -p /etc/passport
openssl rand 32 | sudo tee /etc/passport/key > /dev/null
sudo chmod 600 /etc/passport/key

# Option B: Environment variable
export APP_MASTER_KEY=$(openssl rand -base64 32)
```

### Run

```bash
./bin/passport -config config.yaml
```

On first start, PassPort will:
1. Create a default `config.yaml` if none exists
2. Create and migrate the SQLite database
3. Print a one-time admin password to the log

```
msg="LOCAL ADMIN ACCOUNT CREATED"
msg="Username: admin"
msg="Password: <random>"
msg="This password will NOT be shown again."
```

Log in at `http://localhost:8080/login` and change the admin password immediately.

### Backup & Migration

```bash
# Backup (secrets stay encrypted — same master key required for restore)
passport -config config.yaml -backup passport-backup.json

# Export (secrets decrypted — for migrating to a new system)
passport -config config.yaml -export passport-export.json

# Import (auto-detects backup vs export format)
passport -config config.yaml -import passport-backup.json
```

See the [Backup & Migration guide](docs/guide.md#18-backup--migration) for full details.

## Configuration

PassPort uses a minimal `config.yaml` for startup settings only. All runtime configuration (IDPs, SMTP, MFA, branding, templates, etc.) is managed through the Admin UI and stored in the database.

```yaml
server:
  addr: ":8080"
  # tls_cert: /etc/passport/tls/cert.pem
  # tls_key: /etc/passport/tls/key.pem
  trust_proxy: false
  drain_timeout: 15s

database:
  path: passport.db

logging:
  stdout:
    format: text   # "json" or "text"
    level: info    # "debug", "info", "warn", "error"
  file:
    path: ""       # Set a path to enable file logging
    format: json
    level: debug

session:
  ttl: 8h
  purge_freq: 5m

audit:
  file_path: audit.log
  db_retention: 720h   # 30 days; set to 0 to disable DB purging
  purge_freq: 1h
```

See [docs/guide.md](docs/guide.md) for comprehensive documentation.

## Deployment

### systemd (Recommended)

```bash
# Build the binary
make build

# Run the install script as root
sudo bash deploy/install.sh

# Start the service
sudo systemctl enable --now passport
```

The install script creates:
- System user `passport` (no login shell)
- `/opt/passport/` -- binary, config, database, uploads
- `/etc/passport/key` -- master encryption key
- Systemd unit with security hardening (read-only root, private tmp, no new privileges)

### Reverse Proxy

When running behind nginx, Caddy, or similar, set `trust_proxy: true` in `config.yaml` so PassPort trusts `X-Forwarded-Proto` for secure cookie handling.

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Go 1.26 |
| Router | chi v5 |
| Database | SQLite (modernc.org/sqlite, pure Go) |
| LDAP | go-ldap/ldap/v3 |
| MFA | Duo Universal Prompt SDK |
| CSRF | gorilla/csrf |
| Cron | robfig/cron/v3 |
| Templates | Go html/template + embed.FS |

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
