# Changelog

All notable changes to PassPort are documented in this file.

---

## [v1.1.4] - 2026-04-27

### Added
- **Immediate password change for "must change password at next login"** — When AD returns error code 49 with sub-code 773 (user must change password at next logon) or 532 (password expired), the user is now redirected to an immediate password change form instead of seeing a generic error. Previously, users in this state could not change their password.
- **User-friendly Active Directory error messages** — Specific error conditions from AD bind failures now produce clear, actionable messages:
  - Account locked (sub-code 775): "Your account is locked. Please contact your IT administrator."
  - Account disabled (sub-code 533): "Your account is disabled. Please contact your IT administrator."
  - Account expired (sub-code 701): "Your account has expired. Please contact your IT administrator."
  - Password expired (sub-code 532): Immediate password change redirect (same as 773)
  - Invalid credentials and other bind errors retain the generic message for security.
- **Password complexity hints from AD** — When a password change fails due to AD policy violations, the IDP's configured `password_complexity_hint` is appended to the error message, providing users with guidance on policy requirements.

### Fixed
- **Server fails to start when TLS is not configured** — The default TLS certificate and key paths were hardcoded in the configuration defaults (`/etc/passport/tls/cert.pem` and `/etc/passport/tls/key.pem`), causing the server to attempt loading non-existent files even when TLS was not explicitly configured in `config.yaml`. TLS is now disabled by default; the server runs on HTTP (`:8080`) and only enables TLS when `tls_cert` and `tls_key` are explicitly set in the config file.
- **Duplicate flash message on AD password change failures** — The error message was rendered twice: once from the base layout and again in the card template. The duplicate in the card template has been removed.
- **Password policy error messages not displaying newlines** — When a password change failed due to policy violations, the multi-line error message displayed as a single line with escaped newlines. Flash alerts now use `white-space: pre-wrap` to preserve and wrap newlines while fitting the container width.

---

## [v1.1.3] - 2026-04-17

### Fixed
- **IDP account not auto-linked when MFA is enforced on login** — Users logging in via an IDP with MFA-on-login enabled were presented with the "Link Account" form instead of the "Change Password" form on the dashboard. The self-mapping and correlation logic ran after the MFA redirect in `loginProvider`, so the account was never linked before the early return. Both blocks are now executed before the MFA redirect, ensuring the mapping is persisted on every successful authentication regardless of whether MFA is required.
- **Audit log Provider column always blank** — `ListAudit` now `LEFT JOIN`s `identity_providers` so that the provider friendly name is resolved for all existing rows that have a `provider_id` but no stored `provider_name`. Going forward, `audit.Logger` resolves and stores `ProviderName` at write time by looking up the IDP record, so the value is also present in the flat `audit.log` file.
- **Audit log Provider Name missing in Entry Details modal** — the modal read `ProviderName` from the table row data attribute, which was blank for the same reason as above. Both the read and write path fixes above ensure it is now populated.
- **`GetIDP` lookup failure in audit logger silently swallowed** — if the IDP record could not be fetched when resolving a provider name at audit write time, the error was discarded without any log entry. It is now logged at `Warn` level.
- **Correlation pre-flight DB failures invisible** — when `ListEnabledIDPs` or `ListMappings` failed before spawning the background correlation goroutine, the code silently fell back to running correlation with no log output. Both failure paths are now logged at `Warn` with the originating error.

### Added
- **Provider filter on audit log page** — a Provider dropdown has been added to the audit log filter bar. `AuditFilter` gains a `ProviderID` field; the handler loads the IDP list and passes it to the template; the selection is preserved across filter submissions.
- `"self-mapping created"` promoted from `DEBUG` to `INFO` so auto-link events are visible in production log output without enabling debug mode.

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
