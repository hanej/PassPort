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
- **Unified dashboard** -- users see all linked directory accounts in one place, organised into collapsible provider groups
- **Automatic password policy detection** -- reads the effective policy from AD or FreeIPA and shows users a live rule checklist as they type
- **Forgot-password flow** -- self-service reset with optional Duo MFA verification
- **Optional MFA on login** -- require a second factor for directory logins, not just resets
- **Password expiration notifications** -- cron-scheduled emails with per-IDP templates
- **Automatic account correlation** -- links user accounts across IDPs using configurable attribute rules
- **Web Link providers** -- surface external self-service portals as cards alongside real directories
- **Markdown descriptions** -- format provider descriptions and password hints with a built-in editor toolbar
- **LDAP directory browser** -- browse and search directory trees from the admin UI
- **Whitelabel branding** -- custom title, logo, subtitle, footer text, per-IDP logos
- **Rich email templates** -- TinyMCE editor with preview, per-IDP overrides, template variables
- **Audit logging** -- dual output to append-only JSON file and database with retention controls
- **Admin groups** -- map LDAP groups to the admin role
- **Backup & migration** -- CLI export/import with encrypted or plaintext secrets, web UI with section selection
- **Single binary** -- embedded SQLite, embedded templates and static assets, no runtime services beyond your directory and SMTP server
- **Security hardened** -- AES-256-GCM encryption, CSRF protection, rate limiting, secure cookies, systemd hardening

> **Browser note:** the UI loads Bootstrap, Bootstrap Icons, and TinyMCE from `cdn.jsdelivr.net`. Browsers on an air-gapped network will render the pages unstyled.

## Quick Start

### Prerequisites

- Go 1.26+
- OpenSSL (for master key generation)

> **Note:** PassPort has only been tested on Linux. It builds and runs on macOS and Windows, but production deployment is only supported on Linux systems.

### Build

```bash
make build
```

This produces `bin/passport`. Cross-compile for Linux, macOS, and Windows with `make build-all`.

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

The generated config listens on `:8443` and expects TLS certificates at `/etc/passport/tls/`, which the RPM/DEB package's `postinstall` script creates. To run outside that layout, point `tls_cert`/`tls_key` at your own certificates or blank both to fall back to plain HTTP.

Log in at `https://localhost:8443/login` and change the admin password immediately.

### Backup & Migration

```bash
# Backup (secrets stay encrypted — same master key required for restore)
passport -config config.yaml -backup passport-backup.json

# Export (secrets decrypted — for migrating to a new system)
passport -config config.yaml -export passport-export.json

# Import (auto-detects backup vs export format)
passport -config config.yaml -import passport-backup.json
```

See the [Backup & Migration guide](docs/guide.md#20-backup--migration) for full details.

### Renaming an Identity Provider

A provider's slug is its primary key and cannot be changed from the admin UI. Stop the service, back up the database, then rename it offline — every reference, including the uploaded logo, is rewritten in one transaction:

```bash
passport -config config.yaml -rename-idp old-slug=new-slug
```

## Configuration

PassPort uses a minimal `config.yaml` for startup settings only. All runtime configuration (IDPs, SMTP, MFA, branding, templates, etc.) is managed through the Admin UI and stored in the database. Run `passport -example-config` to print the full annotated template.

```yaml
server:
  addr: ":8443"
  tls_cert: /etc/passport/tls/cert.pem
  tls_key: /etc/passport/tls/key.pem
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

local_admin:
  password_history: 14
  min_length: 12
  require_uppercase: true
  require_lowercase: true
  require_digit: true
  require_special: true
```

See [docs/guide.md](docs/guide.md) for comprehensive documentation, including the [full command-line reference](docs/guide.md#command-line-reference).

## Deployment

### systemd (Recommended)

```bash
# Build the binary
make build

# Run the install script as root (installs the unit, then enables and starts it)
sudo bash deploy/install.sh
```

The install script creates:
- System user `passport` (no login shell)
- `/opt/passport/` -- binary, config, database, uploads, logs
- `/etc/passport/key` -- master encryption key
- Systemd unit with security hardening (read-only root, private tmp, no new privileges)

It does **not** create TLS certificates. Either supply your own at `/etc/passport/tls/` or blank `tls_cert`/`tls_key` in `/opt/passport/config.yaml` before the first start. The RPM/DEB packages generate a self-signed certificate for you.

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
| CSRF | filippo.io/csrf |
| Cron | robfig/cron/v3 |
| Templates | Go html/template + embed.FS |

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
