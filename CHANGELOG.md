# Changelog

All notable changes to PassPort are documented in this file.

---

## [Unreleased]

### Security

- **Directory error details no longer reach end users** — `GET /dashboard/idp-status/{id}` returned the raw provider error, which carries the LDAP endpoint, service account DN and result code, to any authenticated user. It now returns a generic `connection failed`. The dashboard password-change and forgot-password reset flows likewise mapped the raw error into the flash message; both now use a fixed set of user-facing messages (policy violation, wrong current password, locked, disabled, generic). The full error is still recorded in the application log and the audit entry.
- **Branding logo upload size is now enforced** — `ParseMultipartForm(5 MB)` only bounded how much of the upload was buffered in memory; anything larger was still streamed to disk in full. The request body is now capped with `http.MaxBytesReader`, so the documented 5 MB limit is real.
- **`/readyz` no longer returns raw database errors** — the readiness probe is unauthenticated and SQLite driver errors embed the database file path. It now returns one of `database unreachable`, `migration state unavailable` or `migrations not complete`; the underlying error is logged.

### Fixed

- **Seven audit actions could not be filtered in the viewer** — `branding_updated`, `idp_group_created`, `idp_group_updated`, `idp_group_deleted`, `idp_groups_arranged`, `config_exported` and `config_imported` were written as bare string literals rather than `audit.Action*` constants, so they were recorded but absent from the Action dropdown. They are now constants and appear in `FilterOptions()` under the Identity Providers and Administration groups, making good on v1.2.0's claim that the filter cannot drift from what the log can contain.
- **`maxPwdAge` lookup documented incorrectly** — the expiration job reads `maxPwdAge` from the domain root object named by the IDP's Base DN, not from the RootDSE, and it does not consult fine-grained password policies. The guide now says so, and warns that a Base DN below the domain root makes the scan fail.
- **Log rotation examples referenced a PID file that PassPort never writes** — the `logrotate` and `newsyslog` samples in the guide pointed at `/run/passport.pid` and mixed `copytruncate` with a `SIGHUP` postrotate. They now use `systemctl reload passport` and the `/opt/passport/logs/` paths that the packages actually ship.

---

## [v1.2.0] - 2026-08-12

### Upgrade Notes

> **⚠️ Back up your database before upgrading.** Migration `007` rebuilds the `identity_providers` table to widen its `provider_type` CHECK constraint — SQLite cannot alter a constraint in place. Eight tables reference this table with `ON DELETE CASCADE`, so this is a higher-risk migration than usual. Stop the service and copy the database file (including the `-wal` sidecar) before starting the new binary:
>
> ```
> systemctl stop passport
> cp /opt/passport/passport.db{,.pre-weblink}
> cp /opt/passport/passport.db-wal{,.pre-weblink} 2>/dev/null
> ```
>
> Copying a live WAL-mode database can produce an inconsistent snapshot, so stop the service first. `passport -backup` is a config-level JSON export, not a byte-level rollback point.

The migration itself is atomic — it runs inside a transaction and does not record its version on failure, so a failed upgrade leaves the original table intact and the old binary can be restarted. Regression coverage in `internal/db/migrate_weblink_test.go` verifies against a simulated pre-upgrade database that all provider columns (including `secret_blob` and timestamps) survive byte-for-byte, that no child rows are cascade-deleted, that `PRAGMA foreign_key_check` stays clean, and that `ON DELETE CASCADE` still fires afterwards.

Two things to be aware of:

- **Foreign key enforcement is disabled for the duration of the migration run** and restored afterwards. This is required because SQLite ignores `PRAGMA foreign_keys` inside a transaction, and without it the table rebuild would cascade-delete every dependent row. Migrations run single-threaded at startup before the HTTP server binds.
- **Downgrading after creating a Web Link provider is not clean.** The schema still permits `weblink`, but a pre-upgrade binary logs `unsupported provider type` at startup and renders a broken login card. No data is lost, but plan the rollback path accordingly.

Migration `009` (provider groups) is purely additive by comparison: it creates an empty `idp_groups` table and adds a nullable `group_id` and a defaulted `display_order` column to `identity_providers`. Every existing provider stays ungrouped and renders exactly as it did before the upgrade, and a downgrade ignores both columns. Migration `010` (Local Admin placement) is likewise additive: it creates an empty single-row `local_admin_placement` table, and until the arrangement is saved the Local Admin card stays ungrouped and renders where it always did. Migration `011` adds a `start_collapsed` column to `idp_groups`, defaulting to `0` so every existing group keeps loading expanded.

### Added
- **Provider groups** — Identity providers can now be sorted into named sections that control how the login page and dashboard are laid out. **Admin > Provider Groups** offers a drag-and-drop arrangement page: drag providers between groups, drag them within a group to reorder, and drag group headings to reorder the groups themselves. The item follows the pointer into its new position as you drag and the target group is highlighted, and releasing outside any group — or pressing Escape — rewinds the layout to where it started. Arrow buttons on every row do the same without dragging, for keyboard and touch use — moving a provider past the top or bottom of its group carries it into the neighbouring one. Groups are drawn as boxes on the login page and dashboard, so it is clear where one ends and the next begins. A group has a name (unique, ignoring case), an optional Markdown description, an optional [Bootstrap Icons](https://icons.getbootstrap.com/) class chosen from a searchable picker covering the full icon set (or typed by hand), and an option to let users collapse it — optionally loading collapsed. Groups are presentational only — they do not affect authentication, correlation, MFA, or permissions. A group with no providers is hidden from users (and flagged as such in the admin UI), providers left unassigned render last with no heading, and deleting a group never deletes its providers — they revert to ungrouped. The whole layout is saved in one transaction, and a stale page referencing a deleted group or provider is rejected outright rather than silently discarding part of the arrangement. Groups and the arrangement are included in backups, exports, and the Migration page; on import, groups are matched by name so importing into an installation that already has groups updates them instead of creating duplicates, and importing a file created before this release leaves the local arrangement untouched.
- **The built-in Local Admin card can be grouped and reordered** — Local Admin previously always rendered last on the login page, below every group, which made it look like a member of whichever group happened to be last. It now appears on the arrangement page as a chip labelled **Built-in** and can be dragged into a group or reordered among ungrouped providers like any other card. Local Admin is a reserved provider ID with no `identity_providers` row, so its placement is stored separately (migration `010`); deleting its group returns it to the ungrouped section rather than hiding it, and it is always rendered even if its placement cannot be read. The placement is carried in backups and exports, with its group referenced by name so it survives an import into a different installation.
- **Provider group icon picker** — The group **Icon** field was a bare text box requiring you to know a [Bootstrap Icons](https://icons.getbootstrap.com/) class name off the top of your head. A **Browse** button now opens a searchable picker covering the full set (~2050 icons), loading them in batches as you scroll; clicking one fills the field and clicking it again clears it, a preview beside the field shows the current choice, and the chosen icon is pinned to the front of the grid so it stays visible. The names are parsed from the same icon stylesheet the pages already link rather than being hardcoded, so the picker cannot drift from the version in use, and a curated subset is shown if that stylesheet is unreachable. The field still accepts any `bi-` class typed by hand.
- **Provider groups can load collapsed** — A collapsible group always started expanded. A **Start collapsed** option now renders it closed on first paint, so a long secondary group can be tucked out of the way while still being one click from open. The option only appears once **Let users collapse this group** is ticked, and is ignored on save otherwise, since a group users cannot expand must never start hidden. As before, the open/closed state is not remembered between visits.
- **Web Link identity provider type** — A new `weblink` provider type lets administrators publish an external site alongside the real directories. A Web Link needs only a slug, friendly name, description, logo, and target URL; selecting it in the admin form hides Connection Settings, Password Settings, Email Notification, Attribute Mappings, Correlation Rule, and the MFA Provider dropdown, and the **Test Connection** button opens the URL in a new window. Web Link cards appear on the login page and dashboard like any other provider but open the target site in a new window instead of prompting for credentials. They are excluded from correlation, password expiration, reports, admin groups, user mappings, and the forgot-password flow. Only absolute `http://` and `https://` URLs are accepted — scheme-relative, relative, and non-web schemes such as `javascript:` and `data:` are rejected on save, and a Web Link with no usable URL is hidden rather than rendered as a dead card.
- **Markdown in identity provider descriptions** — The provider **Description** field is now a multi-line editor with a Markdown toolbar (bold, italic, inline code, link, bulleted list, numbered list, plus a syntax reference popover), and descriptions render as formatted HTML on the login page, dashboard, and forgot-password page. This makes it possible to put clickable links and short instructions under a provider name — particularly useful for Web Links. Descriptions are rendered through a restricted Markdown pipeline that drops raw HTML and strips dangerous link schemes (`javascript:`, `data:`, `vbscript:`, `file:`), because they are displayed on the unauthenticated login page; this is deliberately stricter than the password complexity hint field, which still permits inline HTML. Provider cards were restructured to use an overlay link so that links inside a description remain clickable without producing invalid nested anchors.
- **Markdown toolbar on the Password Complexity Hint field** — The hint field previously offered only a syntax help popover. It now has the same toolbar as the description field, plus an **Underline** button, since this field is rendered with inline HTML enabled and therefore supports `<u>text</u>`.
- **`-rename-idp` CLI flag** — An identity provider's slug is its primary key and cannot be changed from the admin UI. `passport -rename-idp old-slug=new-slug` now renames one offline and exits without starting the server. The slug is referenced by eleven columns across nine tables — three of which (`user_idp_mappings.auth_provider_id`, `correlation_warnings.target_idp_id`, `sessions.provider_id`) have no foreign key constraint and so are not caught by `PRAGMA foreign_key_check` if missed. No foreign key declares `ON UPDATE CASCADE`, so the rename runs in a single transaction with deferred foreign key enforcement and verifies the result before reporting success; a failure rolls back and changes nothing. The uploaded logo, whose filename embeds the slug, is moved and `logo_url` updated; a logo pointing elsewhere is left alone. `audit_log` is deliberately not rewritten, since those rows record what happened under the old ID. Stop the service before running it — providers are loaded into an in-memory registry at startup.
- **Provider descriptions now appear on the dashboard** — Descriptions rendered on the login page and forgot-password page but were dropped from the dashboard's provider accordion, so the same card carried different information depending on where you saw it. Each accordion item now shows its description beneath the heading, through the same restricted Markdown pipeline used elsewhere.
- **Automatic password policy detection** — The live rule checklist on the change-password, reset-password, and forced-change pages, and the minimum-age gate on self-service resets, now resolve the rules the directory will actually apply to *that* user rather than assuming the values configured in PassPort. An unreadable policy is treated as unknown: the checklist is omitted and the user is not blocked, since the directory remains the authority on whether a password is acceptable.

  Against **Active Directory**, the connector reads the user's `msDS-ResultantPSO` and takes the minimum length, complexity switch, and minimum age from that fine-grained policy when one applies, falling back to the domain head — which is located through the RootDSE `defaultNamingContext` rather than assuming the configured base DN is the domain itself. Complexity comes from `msDS-PasswordComplexityEnabled` on a PSO and from bit 0 of `pwdProperties` (`DOMAIN_PASSWORD_COMPLEX`) on the domain; MS-ADTS 3.1.1.13.1 fixes the remainder of the rule at three character categories plus the account-name and display-name check.

  Against **FreeIPA / Red Hat IdM**, the connector resolves the policy the same way the directory does: the user's `krbPwdPolicyReference` when the service account is allowed to read it, otherwise the Class of Service template for their highest-priority group, otherwise `cn=global_policy` under the Kerberos realm container, which is located by searching for the realm rather than assuming it is the base DN uppercased. `krbPwdMinLength` gives the minimum length, `krbPwdMinDiffChars` the number of character classes, `ipaPwdUserCheck` the account-name check, and `krbMinPwdLife` the minimum age. A password that has already expired is exempt from the age gate, since that is exactly when the user has to be able to set a new one. This needs the **Password Policy Readers** privilege on the service account; without it the policy is unreadable and the checklist is omitted rather than the user being blocked.
- **Self-service resets now enforce the minimum password age themselves** — The reset flow stages a temporary password before the user's own change, which moves the account's password-age clock to now and would make that change illegal under a non-zero minimum age. PassPort now clears the clock (`pwdLastSet = 0` on Active Directory — only `0` or `-1` are writable, so the original timestamp cannot be restored) and applies the equivalent gate itself beforehand, since without it a user could cycle through the password history to reuse an old password. A reset attempted too soon is refused with the date the directory will next accept a change, and is recorded in the audit log. Password history and complexity are still enforced by the directory on the change itself.
- **Temporary passwords are raised to the directory's minimum length** — The temporary password staged during a reset was generated from the length configured on the identity provider, which a fine-grained policy can exceed. Length is enforced even on an administrative reset, so the reset failed outright. The generator now takes the larger of the configured and discovered minimums; a directory whose minimum cannot be read leaves the configured length in place.
- **`scripts/ad_policy_check.go` diagnostic helper** — A standalone, build-tagged tool that verifies against a live directory the assumptions the reset flow depends on: whether an administrative `Replace` of `unicodePwd` moves `pwdLastSet`, whether a service-bound `Delete`+`Add` change is subject to the minimum password age, whether clearing `pwdLastSet` exempts the account, and whether complexity and history are enforced on each path. It can read the service account credential straight out of the PassPort database so it never has to be exported in plaintext, and it also reports the resolved maximum password age. It changes the target account's password several times and consumes history slots, so it requires `-confirm` and a disposable test account.

### Fixed
- **A forced Active Directory password change could bypass password history** — When a user's own bind is rejected because the account is in a must-change or expired state, the change is completed over the service account. That path used a `Replace` of `unicodePwd`, and Active Directory derives set-versus-change semantics from the modify form rather than the bound identity (MS-ADTS 3.1.1.3.1.5) — so a `Replace` was treated as an administrative *reset*, which skips password history and minimum age entirely. It now sends the `Delete`(old) + `Add`(new) pair, which the directory treats as a change and enforces in full.
- **A withheld fine-grained policy attribute was read as "no policy"** — When a user's `msDS-ResultantPSO` resolved but the Password Settings Container was not readable by the service account, LDAP reported the withheld attribute as simply absent and the minimum age was taken to be unset. That silently dropped the check for exactly the restricted accounts a PSO exists to cover. An empty attribute on a PSO that did resolve is now an error naming the read access to grant.
- **The password complexity hint was shown as raw Markdown on the forced AD password change page** — Every other page renders this field as Markdown. The forced-change page — the one users are sent to precisely when they must satisfy those rules — printed the raw source, so a hint using bold or a bulleted list arrived as literal asterisks. It now renders like the rest.
- **Saving a provider with no correlation rule logged a spurious `ERROR`** — Updating an identity provider always attempts to delete any existing correlation rule when the form has none, and logged the resulting "not found" at `ERROR` even though having no rule is the normal case. This is now ignored. Web Link providers hit this path on every save.
- **Provider ID (slug) validation was silently disabled in current browsers** — The form's `pattern="[a-z0-9-]+"` is an invalid regular expression under the `v` flag that browsers now apply to `pattern`, so it threw a `SyntaxError` and no client-side validation ran at all. The hyphen is now escaped, and the slug is additionally validated server-side on create, since it becomes the `identity_providers` primary key and is interpolated into the uploaded logo filename. The form now also states that the slug cannot be changed after creation.
- **A provider could be created with the reserved slug `local`** — `local` identifies the built-in Local Admin card, which has no `identity_providers` row of its own. The login page and the new arrangement store both branch on that slug, so a real provider claiming it was rendered and reordered as Local Admin instead of itself. Both the admin form and `-rename-idp` now reject it.
- **The password rule checklist described Active Directory's rules regardless of the directory** — The checklist hardcoded "Three of: uppercase, lowercase, number, symbol" and always showed the name rule, because both are fixed in Active Directory. FreeIPA makes the category count configurable and the name check a separate switch, so the checklist now renders the count the directory actually reported and shows the name rule only when it applies. FreeIPA permits up to five classes, the fifth being characters outside printable ASCII; since that is not something a checklist can sensibly ask for, a policy of five is displayed as four.
- **An expanded provider accordion left its heading tinted and ringed in blue** — Bootstrap's default active background made the open heading on the dashboard and reports pages look like selected text, and the click that expanded it left the button focused, so its focus ring read as a stray blue border. The heading now stays neutral when expanded; the focus ring is still drawn for keyboard navigation.
- **Most of the audit log could not be filtered by action** — The Action dropdown listed five hardcoded options, two of which (`link_account`, `admin_config`) were never recorded and so always returned an empty log, while the thirty-odd actions that *are* recorded — password resets, account unlocks, provider and MFA changes, admin group changes, email template edits, scheduled jobs — had no entry at all. The filter is now generated from the action constants themselves and grouped by area, so it cannot drift from what the log can contain.
- **Backups silently dropped the expired-notice setting** — `days_after_expiration`, which controls whether users keep being reminded after their password has already expired, was missing from the export format. Backing up and restoring, or migrating to a new server, reset it to `0` and quietly stopped those notices. The field now round-trips; files written before this release simply restore as disabled, which is what they already meant.

### Security
- **Password changes are now rate limited** — `POST /ad-change-password` and `POST /dashboard/change-password` were unthrottled while the login and reset-link endpoints were not. Each of those requests binds to the directory with the user's *current* password, so a script looping over guesses could drive the account into lockout, and each one costs a directory round trip. Both are now limited to one attempt per five seconds with a burst of five — a burst chosen to stay under the common Active Directory lockout threshold. The limiter is keyed on the authenticated account rather than the client IP, so one user cannot exhaust the budget for everyone else behind the same NAT or reverse proxy. The `GET` forms are unaffected.
- **Dependencies refreshed** — `go-ldap/ldap` v3.4.13 → v3.4.14, `goldmark` v1.8.4 → v1.8.5, `golang.org/x/crypto` v0.54.0 → v0.55.0, and `modernc.org/sqlite` v1.53.0 → v1.56.0, along with their transitive updates (`modernc.org/libc`, `modernc.org/memory`, `go-asn1-ber/asn1-ber`, `mattn/go-isatty`). `govulncheck` reports no known vulnerability reachable from this code.

### Improved
- **The password rule checklist now appears on the dashboard** — Previously the live checklist of directory rules was shown only on the forgot-password reset page and the forced change page after an expired Active Directory password. The dashboard change-password panel, the form most users actually use, offered nothing but the administrator's free-text hint. Each panel now resolves and displays the policy for its own linked account. A per-IDP **Show discovered password rules** switch under *Password Settings* turns the checklist off for administrators who would rather write their own hint; it is on by default, and turning it off also skips the directory lookup.
- **A missing FreeIPA read privilege is now reported on Test Connection** — Password policies in FreeIPA are readable only with the *Password Policy Readers* privilege, and LDAP reports a withheld attribute as simply absent. A service account without it produced a healthy-looking connection while the rule checklist and the minimum-age gate went quietly missing. Test Connection now reads the global policy and returns a warning naming the privilege to grant.
- **Skipped policy checks are recorded as warnings, not failures** — When the minimum password age cannot be verified the reset still proceeds, but the audit entry claimed the reset had failed. It is now recorded as a new `warning` result, which the audit log displays and filters alongside success and failure. The matching per-request log lines dropped from `WARN` to `DEBUG`, since Test Connection is now the place an administrator discovers the cause.
- **Password failures now log the directory's own error** — Active Directory folds complexity, history, and minimum age into a single opaque `0000052D`, so the sentinel error PassPort raised was indistinguishable between them and the cause was unrecoverable from the logs. Every `unicodePwd` failure — user-bind change, service-bind change, and administrative reset — now logs the raw LDAP error at `ERROR` alongside the DN and which form was used, and the message shown to the user names all three possibilities instead of a generic "does not meet your organization's requirements".
- **Applied migrations are now checksummed** — The migration runner keyed only off the integer version, so a migration file that was renumbered or edited after shipping was skipped forever against a database that had already recorded that version — leaving a schema that did not match the code while startup still reported migrations as applied. `schema_migrations` now stores a SHA-256 of each file, and startup fails with an explicit error if a recorded version's content has changed. The column is added automatically; rows written before this release carry an empty checksum and are accepted as unverifiable.
- **Read connections are no longer reopened under load** — The read-only connection pool allowed ten open connections but inherited the `database/sql` default of two *idle* ones, so any burst past two concurrent reads closed and reopened the database file and replayed every startup `PRAGMA` on each extra read. Idle now matches open.
- **Test coverage raised to 95%** — Coverage is gated in CI at 95% of statements. New tests cover the expired-password notification job, the report scheduler's encrypted-credential and filter-compilation paths, the Active Directory minimum-password-age and password-policy lookups against a directory that refuses or withholds reads, the login flow's account-state redirects, and the per-provider email template naming and fallback rules. A regression test also pins the logo upload's path-traversal guard.
- **Documentation brought up to date** — The admin guide now covers automatic password policy detection, the FreeIPA privileges it requires, the Test Connection warning state, the password-change rate limits and what they are keyed on, the `warning` audit result, and the `expired_notification` action. Expired-account notices — the **Days After Expiration** setting, the `password_expired` template type and its `{{.DaysExpired}}` variable — were entirely undocumented and now have their own section. A consolidated command-line reference was added covering every flag, including the previously undocumented `-version` and `-example-config`. Health-check and quick-start examples now match the TLS-on-8443 configuration the installer actually writes, four stale cross-reference links were repointed, and a stranded paragraph on Web Link restrictions moved back into the Web Link section.

---

## [v1.1.9] - 2026-07-17

### Added
- **`-example-config` CLI flag** — PassPort can now print a built-in example `config.yaml` to stdout and exit. The sample configuration is embedded from `cmd/passport/config.yaml.example`, making it easy to generate a starting config without copying from documentation.

### Fixed
- **FreeIPA connector did not accept email/UPN-style usernames** — Unlike the AD connector, `buildUserDN` did not strip an `@domain` suffix, so logging in or linking an account with `user@example.com` against a FreeIPA-backed provider constructed an incorrect DN (`uid=user@example.com,...`) and failed even with the correct password. FreeIPA now strips the domain suffix the same way AD does, fixing this for login, account linking, password changes, resets, and account unlock/enable.
- **Password change/reset notification emails were never sent** — The `password_changed` and `password_reset` email templates existed and were configurable, but no code path ever actually sent them: dashboard password changes, forced AD password changes, and self-service forgot-password resets all completed successfully without triggering an email. Added a shared notification helper that resolves the user's notification email attribute from their IDP and sends the appropriate templated email after each successful password change or reset. Failures to send (SMTP not configured, template missing, etc.) are logged but never block the already-successful password operation.

### Removed
- **`account_locked` / `account_unlocked` email templates** — These templates were never wired up to any feature; no account lockout detection or admin unlock action exists in the app. Removed from the admin email template list and deleted any seeded/customized rows via migration.
- **`forgot_password` email template** — Superseded by `password_reset`. The self-service reset flow generates a temporary password internally to satisfy directory bind requirements but never emails it or shows it to the user, so this template was never sent by any code path. Removed from the admin email template list, deleted any seeded/customized rows via migration, and removed the corresponding dead "Current (Temporary) Password" field markup from the reset password page.

### Security
- **Email subject/recipient header injection** — `email.SendHTML` interpolated the recipient address, subject line, and from name/address directly into raw RFC822 headers without checking for embedded `\r\n` sequences. A directory attribute (e.g. a user's email or username) or an admin-editable template containing a CRLF could inject additional headers (such as `Bcc:`) or otherwise tamper with the outgoing message. `SendHTML` now rejects the send outright if any header value contains a CR or LF.
- **Pagination page-select control was vulnerable to DOM-based script injection** — The audit log pagination dropdown built `window.location.href` by concatenating the selected page value directly into a JavaScript string. The value is now passed through `encodeURIComponent` before use.
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
