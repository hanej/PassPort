# Changelog

All notable changes to PassPort are documented in this file.

---

## [v1.1.2] - 2026-04-13

### Fixed
- Preview, Send Now, and logo upload buttons threw a JavaScript null reference error (`Cannot read properties of null (reading 'value')`) after the migration from `gorilla/csrf` to `filippo.io/csrf`. The stale `X-CSRF-Token` header (which read a hidden input that no longer exists) has been removed from all three affected `fetch` calls. CSRF protection continues to work via Fetch metadata headers.
- `-reset-admin-password` and `-force-password-change` CLI flags now exit with a clear error message when the config file does not exist, rather than silently creating a default `config.yaml` that points at an empty database. Use `-config` to specify the path to the existing config file.

---

## [v1.1.1] - 2026-04-13

### Fixed
- `-reset-admin-password` and `-force-password-change` CLI flags failed with `local admin "admin" not found: not found` on a fresh database because `auth.Bootstrap` (which creates the initial admin account) ran after the CLI command handlers. Bootstrap now runs first so both flags work correctly against a newly initialised database.

---

## [v1.1.0] - 2026-04-10

### Added
- **Reports** — expiration and expired-accounts reports per IDP, with configurable schedules, email delivery, and in-UI preview.
- **Export / Import** — full configuration export (secrets decrypted) and backup (secrets stay encrypted) to JSON, plus import from either format. Accessible via `-export`, `-backup`, and `-import` CLI flags.
- **IDP logo upload** — custom logo images can be uploaded per identity provider and served from `/uploads/`.
- **Flash messaging** — success and error flash messages on admin forms.
- **Secure defaults** — TLS and secure cookies are enabled by default; trust-proxy and plaintext modes require explicit opt-in.
- **Local admin password policy** — configurable minimum length, character class requirements, and password history (default: last 14 passwords). Policy is enforced at change time and on the forced-change screen.
- **Password history** — previous password hashes are stored and checked with bcrypt so that recent passwords cannot be reused.
- **CLI admin tools** — `-reset-admin-password <username>` generates and prints a new random password; `-force-password-change <username>` flags the account for a mandatory change at next login.

### Fixed
- Logrotate configuration file was not tracked by git; overly broad `.gitignore` pattern removed.

---

## [v1.0.0] - 2026-04-09

### Added
- Initial public release of PassPort — self-service password management for Active Directory and FreeIPA.
- Web UI for users: forgot password flow, dashboard, MFA (TOTP / email OTP).
- Admin UI: identity provider management, SMTP configuration, MFA providers, branding, email templates, audit log, admin groups, and user mappings.
- SQLite database with automatic migrations.
- Master key encryption for secrets at rest (AES-256-GCM).
- Session management with configurable TTL and purge.
- Dual structured logging: stdout and optional rotating file, independent formats and levels.
- RPM and DEB packaging via `nfpm`; `logrotate` configuration; systemd service unit.
- `-version` flag.
- GitHub Actions CI/CD pipeline with multi-arch builds and GitHub Releases.

### Security
- Migrated CSRF library from `gorilla/csrf` (token-based) to `filippo.io/csrf` (Fetch metadata header-based), eliminating CVE-2025-24358 exposure.
- Fixed CodeQL alerts: email header injection, path traversal, DOM XSS, and overly permissive CI workflow permissions.
- Fixed email content injection — body is now encoded with MIME quoted-printable.
