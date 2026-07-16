# Changelog

All notable changes to PassPort are documented in this file.

---

## [Unreleased]

## [v1.1.9] - 2026-07-16

### Added
- **`-example-config` CLI flag** — PassPort can now print a built-in example `config.yaml` to stdout and exit. The sample configuration is embedded from `cmd/passport/config.yaml.example`, making it easy to generate a starting config without copying from documentation.

### Fixed
- **FreeIPA connector did not accept email/UPN-style usernames** — Unlike the AD connector, `buildUserDN` did not strip an `@domain` suffix, so logging in or linking an account with `user@example.com` against a FreeIPA-backed provider constructed an incorrect DN (`uid=user@example.com,...`) and failed even with the correct password. FreeIPA now strips the domain suffix the same way AD does, fixing this for login, account linking, password changes, resets, and account unlock/enable.
- **Password change/reset notification emails were never sent** — The `password_changed` and `password_reset` email templates existed and were configurable, but no code path ever actually sent them: dashboard password changes, forced AD password changes, and self-service forgot-password resets all completed successfully without triggering an email. Added a shared notification helper that resolves the user's notification email attribute from their IDP and sends the appropriate templated email after each successful password change or reset. Failures to send (SMTP not configured, template missing, etc.) are logged but never block the already-successful password operation.

### Removed
- **`account_locked` / `account_unlocked` email templates** — These templates were never wired up to any feature; no account lockout detection or admin unlock action exists in the app. Removed from the admin email template list and deleted any seeded/customized rows via migration.
- **`forgot_password` email template** — Superseded by `password_reset`. The self-service reset flow generates a temporary password internally to satisfy directory bind requirements but never emails it or shows it to the user, so this template was never sent by any code path. Removed from the admin email template list, deleted any seeded/customized rows via migration, and removed the corresponding dead "Current (Temporary) Password" field markup from the reset password page.

### Security
- **Rate limiting and session IP logging could be bypassed by spoofing `X-Forwarded-For`** — `ratelimit.KeyByIP` and the session manager's client IP lookup both trusted a client-supplied `X-Forwarded-For` header unconditionally, regardless of the `trust_proxy` setting. A client could rotate this header on every request to evade per-IP rate limiting and to forge the source IP recorded against its own sessions and audit entries, even when PassPort was not deployed behind a reverse proxy. Both now derive the client IP solely from the resolved connection address.
- **`trust_proxy`-aware client IP resolution was silently broken by the chi v5.3.1 upgrade** — Bumping `go-chi/chi` replaced the deprecated `middleware.RealIP` (which rewrote `r.RemoteAddr`) with `middleware.ClientIPFromXFFTrustedProxies`/`ClientIPFromRemoteAddr`, which only store the resolved IP in the request context. Nothing in the app read that context value, so the `trust_proxy` middleware was effectively dead code and every downstream consumer (audit logging, rate limiting, session IP recording) kept reading the raw, unresolved `r.RemoteAddr`. Added a `mirrorResolvedClientIP` middleware that copies the resolved client IP back onto `r.RemoteAddr` so `trust_proxy: true` now correctly and exclusively trusts one hop of `X-Forwarded-For` from the immediate upstream proxy, everywhere in the app.
- **Go toolchain updated to 1.26.5** and dependencies refreshed: `go-chi/chi` v5.2.5 → v5.3.1, `goldmark` v1.8.2 → v1.8.4, `golang.org/x/crypto` v0.49.0 → v0.54.0, `golang.org/x/sys` v0.42.0 → v0.47.0, `modernc.org/sqlite` v1.48.0 → v1.53.0, `modernc.org/libc` v1.70.0 → v1.73.4.

### Improved
- **AD/FreeIPA connector logging now distinguishes real errors from expected auth outcomes** — Connection failures, service account bind failures, and unexpected bind errors are now logged at `ERROR` instead of `DEBUG`. Expected outcomes (wrong password, locked/disabled/expired account, must-change-password) remain at `DEBUG` since they are normal user-facing conditions, not application errors.
- **More unexpected failures now logged at `WARN`/`ERROR` instead of `DEBUG`** — IDP connectivity checks on the dashboard (`ERROR`, since they always use the service account and never fail due to user error); failure to resolve a user's DN for self-mapping right after a successful login (`WARN`); auto-correlation attribute resolution failures (`WARN`); failure to load, decrypt, or parse saved IDP secrets during connection testing (`WARN`); and requests for a nonexistent email template type (`WARN`). Routine, expected outcomes (wrong password/OTP, form validation errors, user-not-found lookups) remain at `DEBUG`.

## [v1.1.8] - 2026-06-29

### Improved
- **Audit log pagination replaced with page dropdown** — When the audit log spans many pages, the previous row of numbered page links could grow very long. The pagination control now shows a compact **Previous / page selector / Next** layout, right-aligned in the card footer. The dropdown displays "Page N of Total" for each page and navigates immediately on selection.

---

## [v1.1.7] - 2026-06-08

### Fixed
- **Cross-IDP password changes could fail for linked accounts** — Password change lookup required the mapping's `auth_provider_id` to match the current login provider. Users with the same username in multiple IDPs (for example `corp-ad` and `redhat-idm`) could be incorrectly shown as unlinked. Password changes now resolve the linked target account by username + target IDP so the correct mapped account is used.

### Security
- **Go toolchain updated to 1.26.4** — Fixes `GO-2026-5039` (arbitrary inputs included in errors without escaping in `net/textproto`) and `GO-2026-5037` (inefficient candidate hostname parsing in `crypto/x509`).

---

## [v1.1.6] - 2026-06-01

### Added
- **Expired password notifications** — A new "Days After Expiration" setting under Password Expiration Notifications configures how long to keep sending notification emails to accounts whose passwords have already expired. Accepts `0` (disabled), `-1` (indefinitely), or a positive integer (number of days after expiration). Requires database migration 004.
- **`password_expired` email template** — A new global template type with variables `Username`, `ProviderName`, `ExpirationDate`, and `DaysExpired`. Per-IDP overrides follow the same `password_expired:{idpID}` key pattern as the existing warning template.
- **Dry-run "Already Expired" tab** — The Test Filters modal now shows two Bootstrap nav-tabs: "Expiring Soon" (existing behavior) and "Already Expired" (users whose passwords have already passed their expiration date), populated in a single scan.

### Fixed
- **`bufio.Scanner` missing `Err()` check in audit logger test** — The scan loop did not inspect `scanner.Err()` after completion, which could mask I/O errors.
- **Email template preview missing sample data for report and expired templates** — The preview handler did not populate `GeneratedDate`, `AccountCount`, or `ReportTable` for report-type templates, nor `DaysExpired` or `TempPassword` for their respective template types. All sample data variables are now present so every template type renders correctly in the preview modal.
- **PassPort service not restarting on RPM upgrade** — The `postinstall.sh` script enabled the service but did not restart it, causing upgrades to keep the old binary running in memory. Now explicitly calls `systemctl restart passport` after enable, ensuring new binaries load immediately.

---

## [v1.1.5] - 2026-05-31

### Added
- **On-demand password expiration scan** — The "Run Now" button no longer requires the cron schedule to be enabled. Admins can trigger a manual expiration scan even when the scheduled job is turned off, as long as the expiration config exists.

### Fixed
- **Dashboard shows accounts as unlinked when logging in via a different provider** — The dashboard queried mappings filtered by the current auth provider, but mappings are created by whichever provider the user first logged in with. The dashboard now retrieves mappings by username regardless of which provider created them, consistent with how the correlation engine determines linkage.
- **Flash notification bubble too tall** — The `white-space: pre-wrap` style was applied to the entire alert container, causing template indentation whitespace to render as visible space. Moved `pre-wrap` to a span wrapping only the message text and tightened vertical padding.

### Improved
- **Duo MFA Redirect URI help text** — The admin form and documentation now explicitly state that the path must be `/mfa/callback` (hardcoded in the application) to prevent misconfiguration.

### Security
- **Go toolchain updated to 1.26.3** — Fixes 6 standard library vulnerabilities including XSS in `html/template` and DoS in `net/mail`.
- **Updated `github.com/Azure/go-ntlmssp` to v0.1.1** — Fixes a panic on malformed NTLM challenge payloads (integer overflow/wraparound).

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
