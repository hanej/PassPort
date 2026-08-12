# PassPort Administration Guide

Comprehensive documentation for PassPort, a self-service password management tool for Active Directory and FreeIPA.

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Configuration](#2-configuration)
3. [Local Admin Account](#3-local-admin-account)
4. [Identity Providers](#4-identity-providers)
5. [User Dashboard](#5-user-dashboard)
6. [Forgot Password](#6-forgot-password)
7. [MFA Providers](#7-mfa-providers)
8. [Password Expiration Notifications](#8-password-expiration-notifications)
9. [Reports](#9-reports)
10. [Email Configuration](#10-email-configuration)
11. [Email Templates](#11-email-templates)
12. [Admin Groups](#12-admin-groups)
13. [User Mappings](#13-user-mappings)
14. [Audit Log](#14-audit-log)
15. [Branding](#15-branding)
16. [Security](#16-security)
17. [Deployment](#17-deployment)
18. [Logging](#18-logging)
19. [API and Health Checks](#19-api-and-health-checks)
20. [Backup & Migration](#20-backup--migration)

---

## 1. Getting Started

### Prerequisites

- **Go 1.26+** (build time only)
- **OpenSSL** (for master key generation)
- One or more LDAP directories (Active Directory or FreeIPA)
- A modern web browser for the admin UI

### Building

```bash
# Single platform
make build          # Output: bin/passport

# Cross-compile
make build-all      # Outputs: bin/passport-linux-amd64, bin/passport-linux-arm64,
                    #          bin/passport-macos-amd64, bin/passport-macos-arm64,
                    #          bin/passport-windows-amd64.exe
```

The build uses `CGO_ENABLED=0` with `-trimpath -ldflags="-s -w"` to produce a fully static binary.

### First Run

1. **Generate a master key** (see [Security - Master Key Management](#master-key-management))

2. **Start the application:**

   ```bash
   ./bin/passport -config config.yaml
   ```

   If `config.yaml` does not exist, a default one is created automatically.

   > **The generated config expects TLS certificates.** It listens on `:8443` and points `tls_cert`/`tls_key` at `/etc/passport/tls/`, which the package install script populates. Starting outside that layout fails with a missing-file error until you either point those paths at real certificates or blank them both, which drops the server to plain HTTP. Run `passport -example-config` to print the template without starting anything.

3. **Retrieve the initial admin password** from the startup log output:

   ```
   msg="LOCAL ADMIN ACCOUNT CREATED"
   msg="Username: admin"
   msg="Password: Gx9kPm2vT8..."
   msg="This password will NOT be shown again."
   msg="You will be required to change it on first login."
   ```

4. **Log in** at `https://localhost:8443/login` with the `admin` username and the generated password. You will be forced to set a new password immediately that meets the [password policy](#password-policy).

   > **Self-signed certificate:** A self-signed TLS certificate is generated automatically at install time. Your browser will show a security warning on first access. Accept the exception or replace the certificate with a CA-signed one (see [TLS](#tls)).

### What Happens on Startup

PassPort performs the following on every start:

1. Loads or creates `config.yaml`
2. Resolves the master encryption key (env var or filesystem)
3. Opens (or creates) the SQLite database and runs migrations
4. Bootstraps the local admin account if it does not exist
5. Initializes dual audit logging (file + database)
6. Loads all enabled identity providers into the live registry
7. Starts the password expiration cron scheduler
8. Begins listening for HTTP/HTTPS connections

### Command-Line Reference

| Flag | Purpose |
|------|---------|
| `-config <path>` | Path to the configuration file. Default `config.yaml`. |
| `-version` | Print the build version and exit. |
| `-example-config` | Print the example `config.yaml` to stdout and exit. |
| `-backup <file>` | [Back up](#command-line-backup-secrets-stay-encrypted) configuration with secrets left encrypted, then exit. |
| `-export <file>` | [Export](#command-line-export-secrets-decrypted) configuration with secrets decrypted, then exit. |
| `-import <file>` | [Import](#command-line-import) a backup or export file, then exit. |
| `-rename-idp <old>=<new>` | [Rename a provider slug](#changing-a-provider-id) offline, then exit. Stop the service first. |
| `-reset-admin-password <user>` | [Reset a local admin password](#cli-reset-admin-password) and force a change at next login, then exit. |
| `-force-password-change <user>` | [Force a local admin to change their password](#cli-force-password-change-at-next-login) at next login, then exit. |

Every flag except `-config` causes PassPort to do its work and exit without starting the web server. The management flags read the database path from the config file, so pass `-config` alongside them on an installed system:

```bash
passport -config /etc/passport/config.yaml -reset-admin-password admin
```

---

## 2. Configuration

PassPort has a split configuration model:

- **`config.yaml`** -- startup settings only (server, database, logging, sessions, audit)
- **Admin UI** -- all runtime settings (IDPs, SMTP, MFA, branding, templates, groups)

Runtime settings are stored in the SQLite database and take effect immediately.

### Full config.yaml Reference

```yaml
server:
  # Listen address.
  addr: ":8443"

  # TLS certificate and key paths. Both must be set together.
  # A self-signed certificate is generated at install time.
  # Replace with a CA-signed certificate for production.
  tls_cert: /etc/passport/tls/cert.pem
  tls_key: /etc/passport/tls/key.pem

  # Enable when running behind a reverse proxy that terminates TLS.
  # Trusts X-Forwarded-Proto to determine connection security.
  # Sets the Secure flag on cookies when the proxy reports HTTPS.
  # Leave false (the default) when PassPort terminates TLS directly.
  trust_proxy: false

  # Grace period for in-flight requests during shutdown.
  drain_timeout: 15s

database:
  # Path to the SQLite database file. Created automatically if it does not exist.
  path: passport.db

logging:
  stdout:
    # Output format: "json" for structured logging, "text" for human-readable.
    format: text
    # Minimum log level: "debug", "info", "warn", "error".
    level: info

  file:
    # File path for log output. Leave empty to disable file logging.
    path: ""
    format: json
    level: debug

session:
  # How long a user session remains valid.
  ttl: 8h
  # How often the background goroutine purges expired sessions.
  purge_freq: 5m

audit:
  # Path to the append-only JSON audit log file. This file is never automatically
  # purged and serves as the permanent audit record.
  file_path: audit.log

  # How long to retain audit entries in the database (for the admin UI viewer).
  # Older entries are automatically purged. Set to 0 to disable DB purging.
  # The file log is unaffected by this setting.
  db_retention: 720h    # 30 days

  # How often the database audit purge job runs.
  purge_freq: 1h

local_admin:
  # How many previous password hashes to retain. Users cannot reuse any of the
  # last N passwords. Set to 0 to disable history checking.
  password_history: 14

  # Minimum password length.
  min_length: 12

  # Character-class requirements.
  require_uppercase: true   # At least one uppercase letter (A–Z)
  require_lowercase: true   # At least one lowercase letter (a–z)
  require_digit: true       # At least one digit (0–9)
  require_special: true     # At least one special character
```

### Configuration Priority

| Setting | Source | Changeable at Runtime |
|---------|--------|----------------------|
| Listen address, TLS | config.yaml | No (restart required) |
| Database path | config.yaml | No (restart required) |
| Log levels and formats | config.yaml | No (restart required) |
| Session TTL | config.yaml | No (restart required) |
| Audit retention | config.yaml | No (restart required) |
| Local admin password policy | config.yaml | No (restart required) |
| Identity providers | Admin UI (database) | Yes |
| SMTP settings | Admin UI (database) | Yes |
| MFA providers | Admin UI (database) | Yes |
| Email templates | Admin UI (database) | Yes |
| Branding | Admin UI (database) | Yes |
| Admin groups | Admin UI (database) | Yes |
| Expiration schedules | Admin UI (database) | Yes |

---

## 3. Local Admin Account

PassPort ships with a single built-in local admin account that is created automatically on first startup. This account is independent of any LDAP directory — it always works even when all IDPs are offline.

### Bootstrap

On first start, PassPort generates a cryptographically random 24-character password and prints it **once** to the log:

```
msg="LOCAL ADMIN ACCOUNT CREATED"
msg="Username: admin"
msg="Password: Gx9kPm2vT8rNqLs4eJhD7mYv"
msg="This password will NOT be shown again."
msg="You will be required to change it on first login."
```

The account is flagged with `must_change_password = true`. You will be redirected to a forced password change screen immediately after the first login.

### Password Policy

All local admin password changes — including the forced change on first login — are subject to the policy defined in `config.yaml` under the `local_admin:` block.

**Defaults:**

| Requirement | Default |
|-------------|---------|
| Minimum length | 12 characters |
| Uppercase letter (A–Z) | Required |
| Lowercase letter (a–z) | Required |
| Digit (0–9) | Required |
| Special character | Required |
| Password history | Last 14 passwords cannot be reused |

The generated bootstrap password itself is recorded in the history, so it cannot be reused as the new password when you change it on first login.

**Special characters** are defined as: `!@#$%^&*()-_=+[]{}|;:',.<>?/\`~"`

Policy violations are shown as inline form errors — PassPort will not save the new password until all requirements are met.

### Password History

Every time a local admin successfully changes their password, the new hash is added to the history and the oldest entry beyond the configured `password_history` limit is removed. PassPort checks each history entry using bcrypt comparison, so the check is resistant to timing attacks.

Set `password_history: 0` in `config.yaml` to disable history checking entirely.

### CLI: Reset Admin Password

If a local admin is locked out, an administrator with shell access can reset the password without starting the web server:

```bash
cd /opt/passport
sudo -u passport bin/passport -config config.yaml -reset-admin-password admin
```

This generates a new random 24-character password, updates the account, flags it as `must_change_password`, records the new hash in the password history, and prints the new password to stdout:

```
Password for "admin" has been reset.
New password: mKp3xQz8vLn2rBw7cJt5eDuh
The account has been flagged to require a password change at next login.
```

The server does **not** need to be running. Any active sessions for that user will lose access on the next request (the session's password hash is no longer valid).

### CLI: Force Password Change at Next Login

To require a local admin to change their password at next login without changing the password itself:

```bash
sudo -u passport bin/passport -config config.yaml -force-password-change admin
```

Output:
```
Account "admin" will be required to change their password at next login.
```

This sets the `must_change_password` flag. The next time the user logs in they will be redirected to the forced password change screen before they can access any other page.

### Managing Multiple Local Admins

You can create additional local admin accounts via **Admin > Identity Providers** (not yet in the UI) or by importing a configuration file. The `-reset-admin-password` and `-force-password-change` flags accept any local admin username, not just `admin`.

---

## 4. Identity Providers

Identity providers (IDPs) are the entries shown to users on the login page and dashboard. Most are LDAP directories that PassPort connects to — each representing a single Active Directory domain or FreeIPA realm — but a **Web Link** is a non-directory provider that simply links out to another site.

The **Admin > Identity Providers** list is sorted by the arrangement you set under **Admin > Provider Groups**, falling back to friendly name for providers you have not arranged. See [Provider Groups](#provider-groups) below.

### Adding an Active Directory IDP

Navigate to **Admin > Identity Providers > Add New** and select **Active Directory**.

| Field | Description | Example |
|-------|-------------|---------|
| Friendly Name | Display name shown to users | `Corporate AD` |
| Description | Markdown subtitle shown under the provider name | `Trouble signing in? See the [policy](https://policy.example.com).` |
| Endpoint | LDAP server hostname and port | `dc01.corp.example.com:636` |
| Protocol | Connection method | `ldaps`, `starttls`, or `ldap` |
| Base DN | Root of the directory tree | `DC=corp,DC=example,DC=com` |
| User Search Base | OU to search for users (optional, defaults to Base DN) | `OU=Users,DC=corp,DC=example,DC=com` |
| Group Search Base | OU to search for groups (optional) | `OU=Groups,DC=corp,DC=example,DC=com` |
| Service Account Username | Bind DN or UPN for the service account | `CN=svc-passport,OU=Service Accounts,DC=corp,DC=example,DC=com` |
| Service Account Password | Password for the service account | (encrypted at rest) |
| TLS Skip Verify | Skip TLS certificate validation | `false` (not recommended for production) |
| Timeout | LDAP operation timeout in seconds | `10` |
| Password Complexity Hint | Markdown text shown to users when changing passwords | `**Min 12 chars** including uppercase, number, special` |
| Random Password Policy | Character classes and length for the MFA reset temp password | see below |

For Active Directory, PassPort uses the `unicodePwd` attribute to set passwords, which requires an LDAPS or STARTTLS connection.

### Adding a FreeIPA IDP

The process is identical except:

- Select **FreeIPA** as the provider type
- Passwords are changed using the LDAP Password Modify Extended Operation
- The service account typically uses `uid=admin,cn=users,cn=accounts,dc=example,dc=com` format
- User search base defaults to `cn=users,cn=accounts,<base_dn>`

### Adding a Web Link

A **Web Link** publishes an external site alongside your directories. It appears on the login page and dashboard as a normal provider card, but clicking it opens the target URL in a new tab instead of prompting for credentials. Use it to surface a related portal, a VPN self-service page, or an internal help desk without leaving PassPort.

Navigate to **Admin > Identity Providers > Add New** and select **Web Link**. Only the Basic Information fields apply:

| Field | Description | Example |
|-------|-------------|---------|
| ID | Slug used in URLs and the audit log | `helpdesk` |
| Friendly Name | Display name shown on the card | `IT Help Desk` |
| Description | Markdown subtitle shown on the card | `Open a [support ticket](https://helpdesk.example.com).` |
| Logo | Optional image shown on the card | (uploaded file) |
| URL | Target site opened in a new tab | `https://helpdesk.example.com` |

Selecting **Web Link** hides the fields that only apply to directories: Connection Settings, Password Settings, Email Notification, Attribute Mappings, Correlation Rule, Password Expiration, and the MFA Provider dropdown.

> **URL restrictions:** Only absolute `http://` and `https://` URLs are accepted. Scheme-relative (`//example.com`), relative (`/path`), and non-web schemes (`javascript:`, `data:`, `file:`, `ftp:`) are rejected and stored as empty. A Web Link with no valid URL is hidden from the login page and dashboard rather than rendering a dead card.

Because a Web Link has no directory behind it, it is excluded from password changes, account linking, correlation, password expiration notifications, reports, admin group membership, and the forgot-password flow. PassPort never sees or handles credentials for the target site — it is only a link.

### Markdown Fields

Two fields accept Markdown, and both have a formatting toolbar above them:

| Field | Where it appears | Toolbar |
|-------|------------------|---------|
| **Description** | Under the provider name on the login page, dashboard, and forgot-password page | Bold, Italic, Inline code, Link, Bulleted list, Numbered list |
| **Password Complexity Hint** | On the change-password and reset-password pages | Bold, Italic, **Underline**, Inline code, Link, Bulleted list, Numbered list |

Each toolbar wraps the current selection, or inserts a placeholder if nothing is selected. The **Link** button inserts `[label](https://)` and preselects the URL so you can type straight over it. The list buttons prefix every selected line. The **?** button on the right opens a syntax reference.

Links in a description open in a new tab and are clickable without selecting the provider card — this is the intended way to point users at a password policy page, a help desk article, or a status page.

> **The two fields do not allow the same syntax.** Descriptions appear on the **unauthenticated** login page, so they are rendered through a restricted pipeline: embedded HTML tags are dropped, and link destinations using `javascript:`, `data:`, `vbscript:`, or `file:` are stripped. The complexity hint is only ever shown to a user who has already authenticated, so it permits inline HTML — which is why it gets an Underline button (`<u>text</u>`) and the description does not.


### Changing a Provider ID

The **Provider ID (slug)** is fixed once a provider is created — the field is read-only when editing, because the slug is the provider's primary key and is referenced by eleven columns across nine tables, three of which carry no foreign key constraint.

Import/export does **not** rename. Import upserts by ID: if the ID in the file does not already exist it creates a new provider, and it never deletes providers that are absent from the file. Changing the ID in an export and re-importing therefore leaves you with two providers, not a renamed one.

Use the `-rename-idp` flag instead. It runs offline against the database and exits without starting the server:

```sh
systemctl stop passport
cp /var/lib/passport/passport.db{,.pre-rename}
sudo -u passport passport -config /etc/passport/config.yaml -rename-idp old-slug=new-slug
systemctl start passport
```

```
Renamed identity provider "helpdesk" to "support-portal".
  admin_groups.idp_id                    1
  sessions.provider_id                   1
  user_idp_mappings.auth_provider_id     1
  user_idp_mappings.target_idp_id        1
  total rows updated                     5
  logo                                   /uploads/idp-logo-support-portal.png
Audit log entries still reference the old ID, which preserves the historical record.
```

> **Stop PassPort first.** Providers are loaded into an in-memory registry at startup, so renaming underneath a running instance leaves it serving the old ID. Back up the database while the service is stopped — copying a live WAL-mode database can produce an inconsistent snapshot.

What the command does:

- Rewrites the slug in `identity_providers` and in every table that references it: attribute mappings, correlation rules, expiration configuration and filters, admin groups, report configuration and filters, user account links (both `target_idp_id` **and** `auth_provider_id`), correlation warnings, and sessions. The whole rename runs in one transaction with deferred foreign key enforcement, then verifies the result with `PRAGMA foreign_key_check`. A failure rolls back and changes nothing.
- Moves the uploaded logo, whose filename embeds the slug (`uploads/idp-logo-<slug>.<ext>`), and updates `logo_url`. A logo pointing somewhere else — an external URL, for example — is left alone.
- Validates the new slug the same way the admin form does: lowercase letters, numbers, and hyphens. `local` is reserved for the built-in admin account and is refused.
- Refuses to run if the provider does not exist, or if the new slug is already taken.

What it deliberately does **not** do:

- **Rewrite `audit_log`.** Audit rows record what happened under the old ID; rewriting them would falsify the historical record.
- **Update anything outside the database.** If you reference the slug in external monitoring, bookmarks, or documentation, update those yourself.

The alternative is to delete and recreate the provider, but that cascades: attribute mappings, correlation rules, expiration configuration and filters, admin groups, user account links, and report configuration are all deleted, and users must link their accounts again.

### Random Password Policy

During the forgot-password MFA flow, PassPort generates a temporary password, resets the user's account to it (via the service account), and pre-fills it as the current password on the reset form. The user then changes their password using that temp value, which enforces the directory's own password complexity rules.

The Random Password Policy controls what that generated temp password looks like. Configure it per IDP under **Admin > Identity Providers > Edit > Settings**.

| Field | Description | Default |
|-------|-------------|---------|
| Uppercase (A–Z) | Include uppercase letters in the temp password | Enabled |
| Lowercase (a–z) | Include lowercase letters in the temp password | Enabled |
| Digits (0–9) | Include numeric digits in the temp password | Enabled |
| Allowed Special Characters | Characters to include verbatim; leave blank to exclude specials | `!@#$%^&()` |
| Length | Length of the generated password (1–99 characters) | `16` |

At least one character class must be enabled. If a directory's password policy prohibits certain characters (for example, some systems reject `!` or `@`), remove them from the special characters field or leave it blank.

> **Note:** These settings only affect the auto-generated temporary password used during the forgot-password MFA flow. They do not restrict what users can set as their new password.

The same **Password Settings** card also holds the complexity hint and the **Show discovered password rules** switch, both of which *are* shown to users — see [Password Complexity Hints](#password-complexity-hints) and [Automatic Password Policy Detection](#automatic-password-policy-detection).

### Connection Protocols

| Protocol | Port | Description |
|----------|------|-------------|
| `ldaps` | 636 | TLS from connection start (recommended) |
| `starttls` | 389 | Plain LDAP upgraded to TLS via STARTTLS |
| `ldap` | 389 | Unencrypted (not recommended, passwords in cleartext) |

### TLS Skip Verify

When `tls_skip_verify` is enabled, PassPort will not validate the LDAP server's TLS certificate. This is useful for development or when using self-signed certificates but should not be used in production without understanding the risk.

### Service Accounts

The service account needs sufficient privileges to:

- Search users in the configured search bases
- Read user attributes (memberOf, mail, sAMAccountName/uid, etc.)
- Modify the password attribute (unicodePwd for AD, userPassword for FreeIPA)
- Read group membership
- Modify lockoutTime and userAccountControl (AD only, for unlock/enable)

#### FreeIPA Privileges

FreeIPA does not grant most of these to an ordinary account, so the service account must be given a role. Only the features you actually use need their privilege:

| Feature | Permission required | Shipped privilege that grants it |
|---------|--------------------|-----------------------------------|
| Login, correlation, expiry reports and notifications | *System: Read User Standard / Kerberos / IPA Attributes*, *System: Read User Membership* | Granted to all authenticated users — nothing to do |
| Forgot-password reset | *System: Change User password* | **Modify Users and Reset passwords** |
| Password policy detection | *System: Read Group Password Policy*, *System: Read Group Password Policy costemplate* | **Password Policy Readers** |
| Unlock and enable account | *System: Unlock User* | **User Administrators** |

```bash
ipa role-add 'PassPort Service' --desc='PassPort self-service password management'
ipa role-add-privilege 'PassPort Service' --privileges='Modify Users and Reset passwords'
ipa role-add-privilege 'PassPort Service' --privileges='Password Policy Readers'
ipa role-add-member 'PassPort Service' --users=svc-passport
```

> **Members of `cn=admins` cannot be reset.** FreeIPA's *System: Change User password* permission explicitly excludes them, so the forgot-password flow will fail for those accounts regardless of which role the service account holds. Use `ipa passwd` for administrators.

**Test Connection** verifies the bind, then reads the global password policy. If the policy is unreadable it returns a warning naming the *Password Policy Readers* privilege, so a missing grant is found once here rather than quietly degrading the rule checklist for every user. The write permissions above are not checked, since doing so would mean attempting a write against a real account.

### Attribute Mappings

Each IDP can have attribute mappings that link canonical names to directory-specific attributes. These are used by the correlation engine to match users across directories.

| Canonical Name | AD Example | FreeIPA Example | Notes |
|---------------|------------|-----------------|-------|
| `email` | `mail` | `mail` | Used for expiration notifications |
| `employee_id` | `employeeID` | `employeeNumber` | Used for cross-IDP correlation |
| `username` | `sAMAccountName` | `uid` | Used for cross-IDP correlation |
| `display_name` | `displayName` | `displayName` | Shown on the user dashboard instead of the raw DN |
| `first_name` | `givenName` | `givenName` | Optional |
| `last_name` | `sn` | `sn` | Optional |
| `department` | `department` | `ou` | Optional |
| `title` | `title` | `title` | Optional |
| `phone` | `telephoneNumber` | `telephoneNumber` | Optional |

Configure mappings in **Admin > Identity Providers > Edit > Attribute Mappings**.

When a `display_name` mapping is configured, the user's dashboard card will show their display name (e.g., "Jane Smith") above their username instead of the raw LDAP distinguished name.

### Correlation Rules

A correlation rule defines how PassPort automatically links a user who logs in via one IDP to their account on another IDP. Each target IDP can have one correlation rule.

- **Source Canonical Attribute** -- the canonical attribute name to read from the authenticating IDP
- **Target Directory Attribute** -- the LDAP attribute to search on the target IDP (resolved automatically from the target's attribute mappings, or set explicitly as a fallback)
- **Match Mode** -- matching strategy (exact match)

Example: If a user logs in via AD where `employeeID=12345`, and FreeIPA has `employeeNumber=12345` mapped to the same canonical name `employee_id`, PassPort will automatically link the accounts.

### Test Connection

Use the **Test Connection** button (available on both the create and edit forms) to verify that the service account can bind to the directory before saving.

A test can come back in three states: success, failure, or a **warning** — the bind worked but something optional is missing. The only warning raised today is a FreeIPA service account that cannot read password policies; see [FreeIPA Privileges](#freeipa-privileges). Warnings are recorded in the audit log alongside successes and failures.

For a **Web Link**, there is no directory to test, so the button opens the configured URL in a new tab instead. If the URL is missing or not a valid `http(s)` address, the button reports an error rather than opening anything.

### LDAP Browser

Each enabled IDP has a built-in LDAP directory browser accessible from **Admin > Identity Providers > Browse**. The browser supports:

- Tree navigation from the Base DN downward
- Viewing all attributes of any directory entry
- Searching the directory by keyword

This is useful for verifying search bases, finding group DNs for admin groups, and debugging attribute mappings.

### Enabling and Disabling

Use the toggle on the IDP list page to enable or disable a provider without deleting its configuration. Disabled providers are not shown to users and are excluded from correlation.

### Provider Groups

Once you have more than a handful of providers, a flat list stops being useful. **Admin > Provider Groups** lets you sort providers into named sections and control the order they appear in on the login page and the dashboard.

Groups are purely presentational. They do not affect authentication, correlation, MFA, or permissions — a provider behaves identically whether it is grouped or not.

| Field | Description | Example |
|-------|-------------|---------|
| Name | Heading shown above the group's providers | `Corporate Directories` |
| Description | Optional Markdown blurb under the heading | `Use your **workstation** password.` |
| Icon | Optional [Bootstrap Icons](https://icons.getbootstrap.com/) class name | `bi-building` |
| Let users collapse this group | Renders the heading as a toggle | (checkbox) |
| Start collapsed | Loads the group closed. Only available when the group is collapsible | (checkbox) |

**Browse** next to the Icon field opens a searchable picker covering the whole Bootstrap Icons set (~2050 icons). The names are read from the same stylesheet the pages link, so the picker always matches the version in use. Icons load in batches as you scroll, and the search box filters the whole set. Hovering an icon shows its name. Clicking an icon fills the field, and clicking it again clears it; a preview to the left of the field shows the current choice, and the chosen icon is pinned to the front of the grid. The field also still accepts any `bi-` class typed by hand.

Group names must be unique, ignoring case. Import matches groups by name, so a duplicate would be ambiguous when the configuration is moved to another installation.

#### Arranging Providers

The page shows one card per group plus an **Ungrouped** card at the bottom. Drag a provider between cards to move it, drag it within a card to reorder it, and drag a group heading to reorder the groups themselves. The provider follows your pointer into its new position as you drag and the group you are over is highlighted; releasing outside a list, or pressing Escape, cancels the move and leaves the layout as it was.

The built-in **Local Admin** card appears here too, marked *Built-in*, and can be dragged into a group or reordered alongside ungrouped providers just like a real provider.

The arrow buttons on every row do the same thing without a mouse drag, for keyboard and touch use. Moving a provider past the top or bottom of its group carries it into the neighbouring group, so every placement is reachable without dragging.

Nothing is written until you press **Save Arrangement**. The whole layout is saved in one transaction, so a partial arrangement is never persisted. If the page is stale — a provider or group was deleted in another browser tab — the save is rejected in full rather than silently dropping the missing entries; reload the page and try again.

#### How Groups Render

- Groups appear in the order you arranged them, each with its heading, optional icon, and optional description. A group is drawn as a box so it is clear where it ends and the next section begins.
- Providers you have not assigned to a group appear last, with no heading. There is no "Ungrouped" label on the user-facing pages.
- **A group with no providers is hidden from users.** The admin page marks it *Empty — hidden from users* so you can tell the difference between a hidden group and a missing one.
- A collapsible group starts expanded on every page load unless you tick **Start collapsed**, in which case it loads closed. Either way the collapsed/expanded state is not remembered between visits.
- The **Local Admin** card on the login page appears wherever you arranged it. Until you move it, it renders last, outside every group, as it always did.

#### Deleting a Group

Deleting a group never deletes its identity providers. They move to the ungrouped section and keep appearing for users exactly as before. Only the heading is removed. If Local Admin was in the group, it moves to the ungrouped section too.

Group descriptions are rendered through the same restricted Markdown pipeline as provider descriptions — raw HTML is dropped and dangerous link schemes are stripped — because they appear on the unauthenticated login page. See [Markdown Fields](#markdown-fields).

#### Groups in Backups and Exports

Groups and the arrangement you set travel with `-backup`, `-export`, and the **Admin > Migration** page, including where you placed the Local Admin card. On import, groups are matched by **name**, not by their internal ID: an incoming `Corporate` group updates an existing `Corporate` group instead of creating a duplicate, so importing into an installation that already has groups is safe. Import files created before this feature existed carry no arrangement, and importing one leaves your current grouping untouched. See [Backup & Migration](#20-backup--migration).

---

## 5. User Dashboard

### Logging In

Users log in at `/login` by selecting an identity provider and entering their directory credentials. PassPort authenticates directly against the selected LDAP directory.

On successful login, the correlation engine runs automatically to link or verify the user's accounts across all enabled IDPs.

### Dashboard Overview

The dashboard shows all enabled directory IDPs and the user's link status for each:

- **Linked (auto)** -- automatically correlated via attribute matching
- **Linked (manual)** -- manually linked by the user
- **Unlinked** -- no matching account found; manual linking available

Any configured **Web Link** providers are listed separately as link cards, which open the target site in a new tab. They have no link status because there is no directory account to correlate.

### Changing Passwords

From the dashboard, users can change their password on any linked IDP:

1. Select the target provider
2. Enter the current password (verified against the directory)
3. Enter and confirm the new password
4. The IDP's password complexity hint is displayed if configured, along with a live checklist of the rules read from the directory itself — see [Automatic Password Policy Detection](#automatic-password-policy-detection)

If an MFA provider is enabled, password changes may require MFA verification first.

Password changes are rate limited per account — see [Security](#16-security).

### Linking Accounts

For unlinked providers, users can manually link their account:

1. Click **Link Account** on the unlinked provider
2. Enter the username and password for that directory
3. PassPort verifies the credentials and creates a manual mapping

Manual mappings are re-verified on each login. If the target DN is no longer found in the directory, the mapping is automatically downgraded to unlinked.

### Password Complexity Hints

Each IDP can have a password complexity hint displayed when users change their password or complete the forgot-password reset flow. The hint field supports **Markdown**, so you can use formatting to make requirements easier to scan, and has a formatting toolbar above it.

**Supported syntax:**

| Syntax | Result |
|--------|--------|
| `**bold**` | **bold** |
| `*italic*` | *italic* |
| `` `code` `` | inline code |
| `[text](https://…)` | link |
| `- item` | bullet list |
| `1. item` | numbered list |
| `<u>text</u>` | underline (inline HTML) |
| `&nbsp;` | extra space |

Example hint:

```
**Password requirements:**

- Minimum 12 characters
- At least 1 uppercase letter (A–Z)
- At least 1 number (0–9)
- At least 1 special character (`!@#$%^&`)
```

For the full Markdown syntax reference, see [markdownguide.org/basic-syntax](https://www.markdownguide.org/basic-syntax/).

### Automatic Password Policy Detection

Alongside the hint you write yourself, PassPort reads the rules the directory actually enforces and shows them as a live checklist on the change-password and reset-password pages, ticking each rule off as the user types.

| | Active Directory | FreeIPA / Red Hat IdM |
|---|---|---|
| Per-user policy | `msDS-ResultantPSO` (fine-grained password policy) | `krbPwdPolicyReference`, else the Class of Service template for the user's highest-priority group |
| Fallback | Domain head, located via the RootDSE `defaultNamingContext` | `cn=global_policy` under the Kerberos realm container |
| Minimum length | `minPwdLength` / `msDS-MinimumPasswordLength` | `krbPwdMinLength` |
| Character classes | `pwdProperties` bit 0 — fixed at 3 of 4 when enabled | `krbPwdMinDiffChars` — any count from 1 to 5 |
| Name check | Implied by complexity (MS-ADTS 3.1.1.13.1) | `ipaPwdUserCheck`, a separate switch |
| Minimum age | `minPwdAge` / `msDS-MinimumPasswordAge` | `krbMinPwdLife` |

The resulting rules are shown as a live checklist on every form that sets a password: the dashboard change-password panel, the forgot-password reset page, and the forced change page after an expired AD password. **Show discovered password rules** under *Password Settings* turns this off per IDP, leaving only the complexity hint you wrote. It is on by default, and turning it off also skips the directory lookup.

On FreeIPA this needs the **Password Policy Readers** privilege — see [Service Accounts](#service-accounts). Without it the policy entries are invisible and the checklist is simply omitted; **Test Connection** reports this so the missing grant is visible to the administrator.

The checklist is guidance only. The directory remains the authority on whether a password is acceptable — it alone knows the password history — so if the policy cannot be read the change still proceeds normally. Two FreeIPA rules are not shown: MIT Kerberos counts a fifth character class outside printable ASCII, so a `minclasses` of 5 is displayed as 4; and the libpwquality options (`maxrepeat`, `maxsequence`, `dictcheck` and the character credits) have no checklist equivalent. Use the complexity hint to describe those.

The minimum age is also enforced by PassPort during a self-service reset. That flow stages a temporary password through the service account, which exempts the subsequent change from the directory's own minimum-age check in both AD and FreeIPA; without an equivalent gate a user could cycle through the password history to reuse an old password. A user blocked this way is told when their next change will be allowed. If the policy cannot be read the reset continues and the audit log records that the gate was skipped, as a **Warning** result rather than a failure.

---

## 6. Forgot Password

The forgot-password flow allows users to reset their directory password without logging in.

### Flow Without MFA

1. User navigates to `/forgot-password`
2. Selects an identity provider
3. Enters their username
4. PassPort verifies the user exists in the directory
5. A temporary reset session is created
6. User is redirected to the reset-password page
7. User enters and confirms a new password
8. The password is reset using the service account (no current password required)

> **Security warning:** Resetting the password in this manner can bypass password complexity rules.

### Flow With MFA

When an MFA provider is enabled, an additional step is inserted after username verification:

1. User navigates to `/forgot-password`
2. Selects an identity provider and enters their username
3. PassPort verifies the user exists in the directory
4. User is redirected to the assigned MFA provider for verification or an email is sent with a one time passcode
5. After successful MFA, the user is taken to the reset-password page
6. Passport resets the user's password with a random password according to the `Random Password Policy` for that IDP using the associated service account
7. User enters and confirms a new password
8. The password is reset using the user's personal account with the random password as the current password to enforce password complexity rules in the IDP

The MFA step ensures that even without the current password, the user must prove their identity through a second factor before a reset is permitted.

### Rate Limiting

The forgot-password endpoint shares the login rate limiter (1 request/second, burst of 10) to prevent brute-force attacks.

---

## 7. MFA Providers

PassPort supports two MFA provider types: **Duo Security** (Universal Prompt) and **Email OTP** (one-time passcode sent to the user's email address). Multiple providers can be configured; each IDP can be assigned a specific provider or fall back to a global default.

### Provider Assignment

Each IDP can be assigned its own MFA provider under **Admin > Identity Providers > Edit > Basic Information**. The resolution order is:

1. The IDP's directly assigned MFA provider (if enabled)
2. The global default set at **Admin > MFA** (if enabled)
3. No MFA required (if neither is configured)

When MFA is active, it is required for the forgot-password flow before a password reset is permitted.

---

### Duo Security

PassPort integrates with Duo using the Duo Universal Prompt (OIDC-based).

#### Setting Up Duo

1. Log in to the [Duo Admin Panel](https://admin.duosecurity.com)
2. Navigate to **Applications > Protect an Application**
3. Search for **Web SDK** and click **Protect**
4. Note the **Client ID**, **Client Secret**, and **API Hostname**
5. Set the **Redirect URI** to `https://your-passport-host/mfa/callback` — the path `/mfa/callback` is required and fixed; only replace the hostname

#### Configuring a Duo Provider

Navigate to **Admin > MFA > Add New** and select **Duo**:

| Field | Description |
|-------|-------------|
| Name | Display name for the provider |
| API Hostname | Duo API hostname (e.g., `api-XXXXXXXX.duosecurity.com`) |
| Client ID | Duo application Client ID |
| Client Secret | Duo application Client Secret (encrypted at rest) |
| Redirect URI | Your PassPort hostname followed by the fixed path `/mfa/callback` (e.g., `https://passport.example.com/mfa/callback`). The path must be exactly `/mfa/callback` — this is hardcoded in the application. Must match exactly what is set in the Duo Admin Panel. |

Use the **Test Connection** button to verify the credentials against the Duo API before saving.

#### How Duo MFA Works

1. PassPort generates a cryptographic state token
2. User is redirected to Duo's hosted authentication page
3. User completes MFA (push notification, passcode, etc.)
4. Duo redirects back to `/mfa/callback` with an authorization code
5. PassPort exchanges the code for a result
6. If the result is "allow", the protected operation proceeds

---

### Email OTP

Email OTP sends a numeric one-time passcode to the user's email address. It requires [SMTP to be configured](#10-email-configuration) and the IDP to have an `email` attribute mapping pointing to the user's email attribute in the directory.

#### Configuring an Email OTP Provider

Navigate to **Admin > MFA > Add New** and select **Email OTP**:

| Field | Description | Default |
|-------|-------------|---------|
| Name | Display name for the provider | |
| OTP Length | Number of digits in the passcode | `6` |
| OTP TTL (minutes) | How long a code remains valid before it expires | `5` |
| Email Subject | Subject line for OTP emails | `Your verification code` |

No secrets are required for Email OTP. A test connection check is not available for this provider type.

#### How Email OTP Works

1. User selects an IDP and enters their username on the forgot-password page
2. PassPort looks up the user's email address from the directory using the `email` attribute mapping
3. A cryptographically random numeric code is generated and stored in the session with an expiry timestamp
4. The code is emailed to the user
5. User enters the code on the verification page
6. PassPort compares the submitted code using constant-time comparison and checks the expiry
7. On success, the session is marked as MFA-verified and the password reset proceeds

A **Resend Code** button is available if the original email is lost or expired. Each resend generates a new code and resets the TTL.

#### Attempt Limits

Each OTP token allows a maximum of **3 verification attempts**. If the wrong code is submitted, the remaining attempts are shown in the error message (e.g., *"Invalid verification code. 2 attempt(s) remaining."*). On the third failed attempt the token is invalidated and the user must click **Resend Code** to receive a new one. Resending resets the attempt counter.

> **Prerequisite:** The target IDP must have an `email` attribute mapping configured (e.g., `mail` for both AD and FreeIPA). If no email attribute is found for a user, the MFA step will fail.

#### Enabling and Disabling

Use the toggle on the MFA provider list to enable or disable a provider. To set a provider as the system-wide default, select it from the **Default Provider** dropdown at the top of the MFA list page.

---

## 8. Password Expiration Notifications

PassPort can scan LDAP directories on a cron schedule to find users with expiring passwords and send email notifications.

### Enabling Notifications

Navigate to **Admin > Identity Providers > Expiration** for the target IDP.

| Field | Description | Example |
|-------|-------------|---------|
| Enabled | Turn the cron job on or off | `true` |
| Cron Schedule | Standard cron expression (5-field) | `0 8 * * *` (daily at 8 AM) |
| Days Before Expiration | Notify users whose password expires within this many days | `14` |
| Days After Expiration | Keep notifying users whose password has *already* expired. `0` disables it, `-1` notifies indefinitely, a positive number stops after that many days | `7` |

### Cron Schedule Syntax

The schedule uses standard 5-field cron syntax:

```
  *    *    *    *    *
  |    |    |    |    |
  |    |    |    |    +--- day of week (0-6, Sunday=0)
  |    |    |    +-------- month (1-12)
  |    |    +------------- day of month (1-31)
  |    +------------------ hour (0-23)
  +----------------------- minute (0-59)
```

Examples:
- `0 8 * * 1-5` -- weekdays at 8:00 AM
- `0 */6 * * *` -- every 6 hours
- `30 7 * * *` -- daily at 7:30 AM

### How Expiration Detection Works

**Active Directory:** PassPort reads the domain's `maxPwdAge` policy from the root DSE, then searches for users whose `pwdLastSet` attribute indicates their password will expire within the configured threshold.

**FreeIPA:** PassPort reads the `krbPasswordExpiration` attribute to determine when each user's password expires.

### Expired Account Notices

A user who ignores every warning stops being notified the moment the password actually expires — which is when they most need telling. **Days After Expiration** keeps the reminders coming on the same cron run:

| Value | Behaviour |
|-------|-----------|
| `0` | Disabled. Only users approaching expiration are notified. This is the default. |
| `-1` | Every expired account is notified on every run, with no cutoff. |
| `N` | Accounts that expired within the last `N` days are notified; older ones are left alone. |

A positive value is usually what you want. `-1` will keep mailing accounts that expired years ago — long-abandoned or service accounts included — unless an exclusion filter catches them.

Expired notices use their own template (`password_expired`) so the wording can differ from the warning email, and are recorded in the audit log as `expired_notification` rather than `expiration_notification`. Exclusion filters apply to both scans.

### Exclusion Filters

Exclusion filters prevent specific users from receiving notifications. Each filter consists of:

| Field | Description | Example |
|-------|-------------|---------|
| Attribute | LDAP attribute to check (`dn`, `distinguishedName`, or any user attribute) | `distinguishedName` |
| Pattern | Regular expression to match | `OU=Service Accounts` |
| Description | Human-readable note | `Skip service accounts` |

If any filter matches, the user is excluded from notification. Filters are evaluated in order; the first match wins.

Examples:
- Exclude service accounts: attribute `distinguishedName`, pattern `OU=Service Accounts`
- Exclude disabled accounts (AD): attribute `userAccountControl`, pattern `514|546|66050`
- Exclude a specific user: attribute `sAMAccountName`, pattern `^admin$`

### Dry Run

The **Dry Run** button scans the directory and evaluates all filters without sending any emails. The results show:

- Total users with expiring passwords
- Which users would be notified
- Which users are excluded and which filter matched
- Each user's expiration date and days remaining

If **Days After Expiration** is set, already-expired accounts are listed separately, with days *since* expiration in place of days remaining.

Use dry runs to verify your filter configuration before enabling the live cron job.

### Running Immediately

The **Run Now** button executes the notification job immediately (outside the cron schedule) and sends real emails. Use this after configuring templates and filters to trigger an immediate scan.

### Per-IDP Email Templates

Each IDP can have its own templates for both messages: `password_expiration` for the warning and `password_expired` for the notice sent after expiration. If no IDP-specific template exists, the global one is used. See [Email Templates](#11-email-templates) for details.

### Schedule Reloading

Cron schedules are reloaded from the database every 5 minutes. Changes made in the admin UI take effect within 5 minutes without a restart. Saving the expiration configuration also triggers an immediate schedule reload.

---

## 9. Reports

Reports are administrator-facing email summaries of account password health across an IDP. Unlike password expiration notifications (which email individual users), reports send a consolidated list of affected accounts to a configured set of recipients.

Two report types are supported per IDP:

| Report Type | Description |
|-------------|-------------|
| **Soon-to-Expire Passwords** | Accounts whose passwords will expire within the configured threshold |
| **Expired Accounts** | Accounts whose passwords have already expired |

Each report type is configured independently per IDP. Navigate to **Admin > Reports**, select an identity provider, then click the report type to configure.

### Configuration Fields

| Field | Description | Default |
|-------|-------------|---------|
| Enabled | Turn the scheduled report on or off | `false` |
| Cron Schedule | Standard 5-field cron expression for when to send the report | `0 7 * * 1` (Mondays at 7 AM) |
| Days Before Expiration | Accounts expiring within this many days are included (Soon-to-Expire only) | `14` |
| Recipients | Comma-separated list of email addresses to send the report to | (empty) |
| Exclude Disabled Accounts | Skip accounts that are disabled in the directory | `true` |

**Active Directory:** When Exclude Disabled is on, PassPort uses the LDAP extensible match `(!(userAccountControl:1.2.840.113556.1.4.803:=2))` filter at the LDAP level.

**FreeIPA:** Disabled account exclusion is handled via exclusion filters (see below). For new FreeIPA report configs, a default filter matching `nsAccountLock=true` is pre-populated.

### Cron Schedule Syntax

Reports use the same 5-field cron syntax as expiration notifications:

```
  *    *    *    *    *
  |    |    |    |    |
  |    |    |    |    +--- day of week (0-6, Sunday=0)
  |    |    |    +-------- month (1-12)
  |    |    +------------- day of month (1-31)
  |    +------------------ hour (0-23)
  +----------------------- minute (0-59)
```

Examples:
- `0 7 * * 1` -- every Monday at 7:00 AM (default)
- `0 8 * * 1-5` -- weekdays at 8:00 AM
- `0 6 1 * *` -- first day of each month at 6:00 AM

### Exclusion Filters

Exclusion filters prevent specific accounts from appearing in the report. Each filter consists of:

| Field | Description | Example |
|-------|-------------|---------|
| Attribute | LDAP attribute to check (`dn`, `distinguishedName`, or any user attribute) | `distinguishedName` |
| Pattern | Regular expression to match | `OU=Service Accounts` |
| Description | Human-readable note | `Skip service accounts` |

If any filter matches a user, that account is excluded from the report. Filters are evaluated in order; the first match wins.

Examples:
- Exclude service accounts: attribute `distinguishedName`, pattern `OU=Service Accounts`
- Exclude a specific account: attribute `sAMAccountName`, pattern `^svc-backup$`
- Exclude FreeIPA disabled accounts: attribute `nsAccountLock`, pattern `(?i)^true$`

### Report Contents

Each sent report includes an HTML table with the following columns:

| Column | Description |
|--------|-------------|
| Display Name | User's display name from the directory |
| Account Name | Login name (`sAMAccountName` for AD, `uid` for FreeIPA) |
| Password Last Set | Date the password was last changed |
| Password Expiration | Date the password expires or expired |
| Days Remaining | Days until expiration (Soon-to-Expire report only; negative = already expired) |
| Last Logon | Most recent logon time (Active Directory only, when available) |

Soon-to-Expire reports are sorted by expiration date (nearest first). Expired Account reports are sorted alphabetically by account name.

If no matching accounts exist when the job runs, the email is skipped entirely.

### Preview

The **Preview** button generates the report HTML using the current directory data and displays it inline without sending any email. Use this to verify filter configuration and check the current account list before enabling the scheduled report.

### Send Now

The **Send Now** button runs the report immediately (outside the cron schedule) and sends it to the configured recipients. SMTP must be configured and enabled for this to work.

### Email Templates

Reports use separate email templates from expiration notifications:

| Template Type | Used For |
|---------------|----------|
| `expiration_report` | Soon-to-Expire Passwords report emails |
| `expiration_report:<idp_id>` | Per-IDP override for the soon-to-expire report |
| `expired_accounts_report` | Expired Accounts report emails |
| `expired_accounts_report:<idp_id>` | Per-IDP override for the expired accounts report |

See [Email Templates](#11-email-templates) for how to edit templates.

### Schedule Reloading

Report cron schedules are reloaded from the database every 5 minutes. Saving a report configuration triggers an immediate reload, so changes take effect without a restart.

---

## 10. Email Configuration

### SMTP Setup

Navigate to **Admin > SMTP** to configure the outbound email server.

| Field | Description | Example |
|-------|-------------|---------|
| Host | SMTP server hostname | `smtp.example.com` |
| Port | SMTP server port | `587` |
| From Address | Sender email address | `passport@example.com` |
| From Name | Sender display name (defaults to "PassPort") | `PassPort Notifications` |
| Username | SMTP authentication username (optional) | `passport@example.com` |
| Password | SMTP authentication password (encrypted at rest) | |
| Use TLS | Direct TLS connection (typically port 465) | `false` |
| Use STARTTLS | Upgrade plaintext to TLS (typically port 587) | `true` |
| TLS Skip Verify | Skip TLS certificate validation | `false` |
| Enabled | Master switch for all email functionality | `true` |

### Connection Modes

| Mode | Typical Port | Description |
|------|-------------|-------------|
| Plain | 25 | No encryption (not recommended) |
| STARTTLS | 587 | Connect plaintext, upgrade to TLS |
| TLS | 465 | TLS from connection start (SMTPS) |

Only one of `Use TLS` and `Use STARTTLS` should be enabled. If neither is set, the connection is unencrypted.

### Authentication

If both username and password are provided, PassPort uses SMTP PLAIN authentication. If omitted, the connection proceeds without authentication (for relays that accept unauthenticated mail from trusted IPs).

### Test Email

Use the **Send Test Email** button to send a test message to a specified address. This verifies the entire SMTP pipeline: DNS resolution, connection, TLS negotiation, authentication, and message delivery.

---

## 11. Email Templates

PassPort uses HTML email templates for all outbound messages. Templates are edited using a TinyMCE rich-text editor in the admin UI.

### Template Types

| Type | Used For |
|------|----------|
| `password_expiration` | Password expiration warning emails |
| `password_expiration:<idp_id>` | Per-IDP override for expiration warnings |
| `password_expired` | Notices sent after a password has already expired |
| `password_expired:<idp_id>` | Per-IDP override for expired notices |
| `expiration_report` | Soon-to-Expire Passwords report emails |
| `expiration_report:<idp_id>` | Per-IDP override for the soon-to-expire report |
| `expired_accounts_report` | Expired Accounts report emails |
| `expired_accounts_report:<idp_id>` | Per-IDP override for the expired accounts report |

### Available Template Variables

Variables are inserted using Go template syntax: `{{.VariableName}}`.

**Password Expiration Templates:**

| Variable | Description | Example |
|----------|-------------|---------|
| `{{.Username}}` | User's login name | `jdoe` |
| `{{.ProviderName}}` | Friendly name of the IDP | `Corporate AD` |
| `{{.ExpirationDate}}` | Formatted expiration date and time | `Jan 15, 2026 3:00 PM EST` |
| `{{.DaysRemaining}}` | Number of days until expiration | `7` |

**Expired Password Templates (password_expired):**

| Variable | Description | Example |
|----------|-------------|---------|
| `{{.Username}}` | User's login name | `jdoe` |
| `{{.ProviderName}}` | Friendly name of the IDP | `Corporate AD` |
| `{{.ExpirationDate}}` | When the password expired | `Jan 15, 2026 3:00 PM EST` |
| `{{.DaysExpired}}` | Number of days since expiration | `3` |

> `{{.DaysRemaining}}` is not available in an expired template, and `{{.DaysExpired}}` is not available in a warning template. Referencing the wrong one leaves it blank rather than failing to send.

**Report Templates (expiration_report and expired_accounts_report):**

| Variable | Description | Example |
|----------|-------------|---------|
| `{{.ProviderName}}` | Friendly name of the IDP | `Corporate AD` |
| `{{.GeneratedDate}}` | Date and time the report was generated | `Apr 9, 2026 7:00 AM EDT` |
| `{{.ReportTable}}` | Pre-rendered HTML table of affected accounts | (HTML) |
| `{{.AccountCount}}` | Number of accounts in the report | `12` |

### Editing Templates

1. Navigate to **Admin > Email Templates**
2. Click **Edit** on the desired template type
3. Modify the subject line and HTML body using the TinyMCE editor
4. Click **Save**

The TinyMCE editor provides full HTML editing capabilities including formatting, links, images, tables, and raw HTML source editing.

### Previewing

Use the **Preview** button to render the template with sample data. This shows exactly how the email will appear to recipients without sending anything.

### Per-IDP Overrides

To customize an email for a specific IDP, create a template with the IDP-specific type suffix (e.g., `password_expiration:<idp_id>`, `expiration_report:<idp_id>`, `expired_accounts_report:<idp_id>`). When the job runs for that IDP, the IDP-specific template takes precedence over the global one.

### Resetting to Defaults

Use the **Reset to Default** button to restore a template to the built-in default. This deletes the custom template from the database, and the system default will be used going forward.

---

## 12. Admin Groups

Admin groups allow directory users to access the admin UI by mapping LDAP groups to the admin role.

### How It Works

1. Navigate to **Admin > Groups**
2. Select an identity provider
3. Enter the full DN of an LDAP group (use the LDAP browser to find it)
4. Add an optional description
5. Click **Add**

When a user logs in, PassPort checks their `memberOf` attribute against all configured admin group DNs. If they are a member of any admin group, their session is granted admin privileges.

### Viewing Members

Click **View Members** on any admin group to see the current members as reported by the directory. This reads the `member` attribute from the group DN in real-time.

### Multiple Groups

You can add multiple admin groups across different IDPs. A user only needs to be a member of one configured group (from any IDP) to gain admin access.

### Local Admin Account

The bootstrap local admin account (`admin`) always has admin access regardless of group membership. This ensures you can always access the admin UI even if LDAP is unavailable.

---

## 13. User Mappings

User mappings track the correlation between a user's authenticating account and their accounts on other IDPs.

### Viewing Mappings

Navigate to **Admin > User Mappings** to search and view all mappings.

- **Search by provider** -- filter mappings by source IDP
- **Search by username** -- find all mappings for a specific user
- **Link type** -- `auto` (created by the correlation engine) or `manual` (created by user)
- **Verified at** -- timestamp of the last successful re-verification

### Auto vs. Manual Links

| Type | Created By | Re-verified |
|------|-----------|-------------|
| Auto | Correlation engine at login | Every login; downgraded if invalid |
| Manual | User via Link Account | Every login; downgraded if DN not found |

### Downgrading

A mapping is "downgraded" (deleted) when re-verification fails. This happens when:

- The target user DN no longer exists in the directory
- The correlation rule has been deleted or changed
- The canonical attribute value no longer matches

The user will see the provider as "unlinked" on their next login and can re-link manually.

### Deleting Mappings

Admins can delete individual mappings or all mappings for a user. This forces re-correlation on the user's next login.

---

## 14. Audit Log

PassPort maintains a dual audit log for all security-relevant events.

### Audited Events

| Action | Description |
|--------|-------------|
| `login` | User login attempt (success/failure) |
| `logout` | User logout |
| `password_change` | Password changed via dashboard |
| `password_reset` | Password reset via forgot-password flow |
| `account_unlock` | Account unlocked |
| `account_enable` | Account enabled |
| `idp_create` | Identity provider created |
| `idp_update` | Identity provider updated |
| `idp_delete` | Identity provider deleted |
| `idp_toggle` | Identity provider enabled/disabled |
| `idp_test_connection` | Connection test performed |
| `smtp_update` | SMTP configuration changed |
| `smtp_test` | Test email sent |
| `admin_group_add` | Admin group mapping added |
| `admin_group_delete` | Admin group mapping removed |
| `link_auto` | Automatic account correlation |
| `link_manual` | Manual account linking |
| `link_failed` | Account linking failed |
| `mapping_reset` | Individual mapping deleted |
| `mapping_reset_all` | All mappings for a user deleted |
| `admin_password_change` | Local admin password changed (forced change, CLI reset, or dashboard) |
| `mfa_create` | MFA provider created |
| `mfa_update` | MFA provider updated |
| `mfa_delete` | MFA provider deleted |
| `mfa_toggle` | MFA provider enabled/disabled |
| `mfa_verify` | MFA verification result |
| `email_template_update` | Email template modified |
| `email_template_reset` | Email template reset to default |
| `expiration_notification` | Expiration email sent |
| `expired_notification` | Already-expired email sent |
| `expiration_config_update` | Expiration config changed |
| `report_config_update` | Report configuration changed |
| `report_sent` | Report email sent to recipients |

### Filtering

The admin audit log viewer at **Admin > Audit** supports filtering by:

- Username
- Action type (grouped by area; the list is generated from the actions above, so it always matches what can be recorded)
- Result (success/warning/failure)
- Provider
- Date range (start/end)

A **warning** marks an action that completed with a caveat rather than one that failed — for example a password reset that went through while the minimum-age check could not be verified.

Results are paginated.

### Retention

Audit data is stored in two places:

| Destination | Retention | Purpose |
|-------------|-----------|---------|
| JSON file (`audit.log`) | Permanent (never purged) | Compliance, forensics |
| SQLite database | Configurable (`audit.db_retention`, default 30 days) | Admin UI viewer |

The file log is append-only and contains one JSON object per line. It is never modified or truncated by PassPort. Use external log rotation tools (e.g., logrotate) if needed.

Database entries older than `db_retention` are automatically purged at the interval set by `audit.purge_freq`.

---

## 15. Branding

PassPort supports whitelabel branding to match your organization's identity.

### Configurable Fields

Navigate to **Admin > Branding** to customize:

| Field | Description | Default |
|-------|-------------|---------|
| App Title | Full application name shown in the header and browser title | `PassPort` |
| App Abbreviation | Short name used in compact layouts | `PassPort` |
| App Subtitle | Tagline shown below the title | `Self-Service Password Management` |
| Logo | Custom logo image (PNG, JPG, SVG, GIF, WebP, or ICO; max 5 MB) | (PassPort default) |
| Footer Text | Text displayed in the page footer | (empty) |
| Primary Color | Main brand color applied to the navbar and primary buttons | `#2c5282` |
| Primary Light Color | Accent color used for hover states and secondary elements | `#3182ce` |

### Custom Colors

The Primary Color and Primary Light Color fields accept any 6-digit hex value (e.g., `#1a3a5c`). Both fields have a color picker for visual selection alongside a hex text input for precise values. Validation enforces the `#RRGGBB` format; invalid values are rejected on save.

Colors are applied at runtime via inline CSS on the navbar element and propagated to Bootstrap utility overrides throughout the UI. Changes take effect immediately without a restart — the next page load reflects the new colors.

**Reset options:**
- Each color field has an individual **Reset** button that restores its factory default
- **Reset All Colors** restores both colors to their defaults at once

A live preview panel on the right side of the branding page updates in real time as you type, showing the navbar and a color-swatch summary before you save.

### Logo Upload

Upload a logo image through the branding form. Accepted formats: PNG, JPG, SVG, GIF, WebP, ICO (max 5 MB). The file is saved to the `uploads/` directory and served at `/uploads/logo.<ext>`. Recommended height: 28–36 px so it fits cleanly in the navbar. Check the **Remove Logo** checkbox to delete the current logo and revert to the default icon.

### Per-IDP Logos

Each identity provider can have its own logo. Set the logo when creating or editing an IDP. Per-IDP logos are displayed on the login page, dashboard, and forgot-password provider selection.

### Where Branding Appears

- Login page header and title
- Dashboard header
- Forgot-password page
- Admin UI header
- Browser tab title
- Page footer

---

## 16. Security

### Master Key Management

PassPort uses a 32-byte (256-bit) master key to encrypt all secrets stored in the database. The master key is resolved at startup using this priority:

1. **Environment variable:** `APP_MASTER_KEY` (base64-encoded 32 bytes)
2. **Filesystem:**
   - Linux: `/etc/passport/key`
   - Windows: `C:\ProgramData\passport\key`

The key file can contain either raw 32 bytes or base64-encoded content (standard or URL-safe encoding, with or without padding).

**Generating a key:**

```bash
# Raw bytes (for file-based key)
openssl rand 32 > /etc/passport/key
chmod 600 /etc/passport/key

# Base64 (for environment variable)
openssl rand -base64 32
```

**Important:** If you lose the master key, all encrypted secrets (LDAP passwords, SMTP credentials, MFA secrets) become unrecoverable. Back up the key securely.

### AES-256-GCM Encryption

All sensitive data is encrypted at rest using AES-256-GCM before being stored in the database. This includes:

- LDAP service account passwords
- SMTP authentication credentials
- Duo MFA client secrets

Each encryption operation uses a unique random nonce. The ciphertext includes the authentication tag for tamper detection.

### CSRF Protection

All state-changing operations (POST requests) are protected by CSRF tokens using [filippo.io/csrf](https://pkg.go.dev/filippo.io/csrf). The CSRF key is deterministically derived from the master key using HMAC-SHA256, so tokens remain valid across server restarts.

### Rate Limiting

PassPort uses in-memory token-bucket rate limiting:

| Endpoint | Rate | Burst | Keyed on |
|----------|------|-------|----------|
| Login (`/login`) | 1 req/sec | 10 | Client IP |
| Forgot password (`/forgot-password`) | 1 req/sec | 10 | Client IP |
| Link account (`/dashboard/link-account`) | 0.5 req/sec | 5 | Client IP |
| Change password (`/dashboard/change-password`) | 0.2 req/sec | 5 | Account |
| Forced change (`/ad-change-password`) | 0.2 req/sec | 5 | Account |

The two password-change endpoints bind to the directory with the user's *current* password, so an unthrottled loop could drive the account into lockout. They are keyed on the authenticated account rather than the client IP, so one user cannot exhaust the budget for everyone else behind the same NAT or reverse proxy; the burst of 5 stays under the common Active Directory lockout threshold. Every other limiter is keyed on the client IP, and login and forgot-password share a single bucket per IP rather than one each. Stale buckets are cleaned up every 10 minutes (30-minute inactivity threshold).

### TLS

PassPort defaults to TLS-only (`tls_cert` and `tls_key` are pre-configured). A self-signed RSA-4096 certificate valid for 10 years is generated automatically at install time by the `postinstall` script:

```
/etc/passport/tls/cert.pem   # Certificate (world-readable)
/etc/passport/tls/key.pem    # Private key  (passport:passport, mode 640)
```

The certificate includes the server's hostname and `localhost`/`127.0.0.1` as Subject Alternative Names.

**Replacing with a CA-signed certificate:**

```bash
# Replace the self-signed files in-place.
# The filenames must remain the same, or update config.yaml.
sudo cp fullchain.pem /etc/passport/tls/cert.pem
sudo cp privkey.pem   /etc/passport/tls/key.pem
sudo chown passport:passport /etc/passport/tls/*.pem
sudo chmod 640 /etc/passport/tls/key.pem
sudo systemctl restart passport
```

### Secure Cookies

Session cookies have the `Secure` flag set when:
- TLS is enabled directly via `tls_cert` and `tls_key` (the default), or
- `trust_proxy` is set to `true` (proxy terminates TLS)

Cookies are always `HttpOnly` and use `SameSite=Lax`.

> **Common misconfiguration:** If `trust_proxy: true` is set but PassPort is accessed directly over HTTP (no proxy), cookies will be marked `Secure` but sent over a plain HTTP connection. The browser will silently discard them, making login appear to work but sessions not persist. Only set `trust_proxy: true` when a TLS-terminating proxy is in front.

### trust_proxy

When `trust_proxy: true`, PassPort trusts the `X-Forwarded-Proto` header from the reverse proxy to determine if the original client connection was over HTTPS. This affects:

- The `Secure` flag on cookies
- CSRF Referer validation

Leave this `false` (the default) when PassPort terminates TLS directly. Only enable it when PassPort is behind a trusted reverse proxy and the proxy is configured to strip or override `X-Forwarded-Proto`.

---

## 17. Deployment

### Directory Layout

```
/opt/passport/
  bin/passport           # Application binary
  config.yaml            # Startup configuration
  passport.db            # SQLite database
  passport.db-shm        # SQLite shared memory (WAL mode)
  passport.db-wal        # SQLite write-ahead log
  audit.log              # Append-only audit log
  uploads/               # Uploaded logos and images

/etc/passport/
  key                    # Master encryption key (600 permissions)
  env                    # Optional environment file for systemd
  tls/
    cert.pem             # TLS certificate (644)
    key.pem              # TLS private key  (640, passport:passport)
```

### Install Script

The provided install script (`deploy/install.sh`) automates setup:

```bash
sudo bash deploy/install.sh
```

It performs:
1. Creates a `passport` system user (no login shell, no home directory)
2. Creates `/opt/passport/bin/`, `/opt/passport/uploads/`, `/etc/passport/tls/`
3. Copies the binary to `/opt/passport/bin/passport`
4. Generates a 32-byte master key at `/etc/passport/key` (if not present)
5. Creates `/etc/passport/env` for optional environment variables
6. Generates a self-signed TLS certificate at `/etc/passport/tls/` (if not present)
7. Sets ownership and permissions
8. Installs the systemd unit file

### systemd Service

The included unit file (`deploy/passport.service`) provides production-ready service management:

```bash
# Start
sudo systemctl start passport

# Enable on boot
sudo systemctl enable passport

# View logs
journalctl -u passport -f

# Check status
sudo systemctl status passport
```

#### Security Hardening

The systemd unit includes the following security directives:

| Directive | Effect |
|-----------|--------|
| `NoNewPrivileges=true` | Prevents privilege escalation |
| `ProtectSystem=strict` | Mounts filesystem read-only except allowed paths |
| `ProtectHome=true` | Hides /home, /root, /run/user |
| `PrivateTmp=true` | Isolated /tmp |
| `PrivateDevices=true` | No access to physical devices |
| `ProtectKernelTunables=true` | No /proc/sys writes |
| `ProtectKernelModules=true` | No module loading |
| `ProtectControlGroups=true` | No cgroup writes |
| `RestrictSUIDSGID=true` | No SUID/SGID binaries |
| `RestrictNamespaces=true` | No namespace creation |
| `LockPersonality=true` | Locks execution domain |
| `MemoryDenyWriteExecute=true` | No W+X memory pages |
| `ReadWritePaths=/opt/passport` | Only writable path |

### Master Key via systemd

Two options for providing the master key:

**Option 1: File-based (recommended)**
The key is read from `/etc/passport/key` automatically. No systemd configuration needed.

**Option 2: Environment variable**
Edit `/etc/passport/env`:
```bash
APP_MASTER_KEY=<base64-encoded-32-byte-key>
```
The unit file includes `EnvironmentFile=-/etc/passport/env` (the `-` prefix means it is not an error if the file is missing).

### Reverse Proxy Setup

When running behind a reverse proxy, configure:

1. Set `trust_proxy: true` in `config.yaml`
2. Configure the proxy to set `X-Forwarded-Proto` and `X-Forwarded-For` headers
3. Proxy all traffic to PassPort's listen address

**nginx example:**

```nginx
server {
    listen 443 ssl;
    server_name passport.example.com;

    ssl_certificate     /etc/ssl/certs/passport.pem;
    ssl_certificate_key /etc/ssl/private/passport.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Caddy example:**

```
passport.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy automatically sets the required headers.

---

## 18. Logging

PassPort supports dual logging with independent configuration for stdout and file output.

### Stdout Logging

Always enabled. Intended for systemd journal or container log collection.

```yaml
logging:
  stdout:
    format: text    # Human-readable for development
    level: info     # Filter out debug noise
```

### File Logging

Optional. Enable by setting a file path.

```yaml
logging:
  file:
    path: /opt/passport/passport.log
    format: json    # Structured for log aggregation (ELK, Splunk, etc.)
    level: debug    # Capture everything for troubleshooting
```

### Log Levels

| Level | Description |
|-------|-------------|
| `debug` | Detailed diagnostic information (LDAP searches, correlation steps, etc.) |
| `info` | Normal operational events (startup, login, password changes) |
| `warn` | Recoverable issues (filter regex errors, mapping verification failures) |
| `error` | Unrecoverable failures (database errors, startup failures) |

Each output (stdout and file) has its own independent level. A common pattern is `info` on stdout for operators and `debug` in the file for troubleshooting.

### Log Format

| Format | Description |
|--------|-------------|
| `text` | Human-readable: `time=... level=INFO msg="http request" method=GET path=/login` |
| `json` | Structured JSON: `{"time":"...","level":"INFO","msg":"http request","method":"GET"}` |

### Request Logging

Every HTTP request is logged with:
- Method and path
- Response status code
- Duration in milliseconds
- Client IP address (respects X-Forwarded-For when `trust_proxy` is enabled)
- Request ID (unique per request, via chi middleware)

### Audit Log vs. Application Log

The application log (`logging` config) and the audit log (`audit` config) serve different purposes:

| | Application Log | Audit Log |
|---|----------------|-----------|
| Purpose | Debugging and operations | Security and compliance |
| Format | Configurable (text/json) | JSON only (file), structured (DB) |
| Content | All application events | Security-relevant events only |
| Retention | External management | File: permanent; DB: configurable |

### Log Rotation

PassPort supports log rotation via the standard `SIGHUP` signal. When the application receives `SIGHUP`, it closes and reopens **both** the application log file and the audit log file, allowing external tools to rotate them safely.

The rotation workflow is:
1. The rotation tool renames the current log files (e.g., `passport.log` → `passport.log.1`, `audit.log` → `audit.log.1`)
2. The tool sends `SIGHUP` to the PassPort process
3. PassPort closes both old file descriptors and opens new files at the original paths
4. The tool optionally compresses the old files

A single `SIGHUP` rotates both files simultaneously. You'll see confirmation in the logs:

```
level=INFO msg="received SIGHUP, reopening log files"
level=INFO msg="application log file reopened"
level=INFO msg="audit log file reopened"
```

#### Linux (logrotate)

Create `/etc/logrotate.d/passport`:

```
/opt/passport/passport.log /opt/passport/audit.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    postrotate
        /bin/kill -HUP $(cat /run/passport.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
```

If you're using systemd and don't have a PID file, use `systemctl` instead:

```
/opt/passport/passport.log /opt/passport/audit.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        /bin/systemctl kill -s HUP passport.service 2>/dev/null || true
    endscript
}
```

Test the configuration:

```bash
sudo logrotate -d /etc/logrotate.d/passport   # dry run
sudo logrotate -f /etc/logrotate.d/passport   # force rotation
```

#### macOS (newsyslog)

Add to `/etc/newsyslog.d/passport.conf`:

```
# logfile                              mode  count  size   when  flags  pid_file          signal
/opt/passport/passport.log             644   30     10240  $D0   J      /run/passport.pid  1
/opt/passport/audit.log                644   30     10240  $D0   J      /run/passport.pid  1
```

Column reference:
- `mode` — file permissions after rotation
- `count` — number of rotated files to keep
- `size` — rotate if file exceeds this size (KB); `*` for no size limit
- `when` — `$D0` = daily at midnight; `$W0` = weekly on Sunday
- `flags` — `J` = compress with bzip2; `Z` = compress with gzip
- `pid_file` — path to PID file (PassPort writes PID here)
- `signal` — signal number to send (`1` = SIGHUP)

If you run PassPort via launchd and don't have a PID file, use a wrapper script:

```
# logfile                              mode  count  size   when  flags  /path/to/script
/opt/passport/passport.log             644   30     *      $D0   JR     /opt/passport/rotate.sh
```

`/opt/passport/rotate.sh`:
```bash
#!/bin/bash
kill -HUP $(pgrep -f "passport.*-config") 2>/dev/null || true
```

#### Windows

Windows doesn't support `SIGHUP`. Use one of these approaches:

**Option 1: Scheduled task with service restart**

Create a PowerShell script `C:\ProgramData\passport\rotate-logs.ps1`:

```powershell
$logDir = "C:\ProgramData\passport"
$date = Get-Date -Format "yyyyMMdd"

# Rotate application log
if (Test-Path "$logDir\passport.log") {
    Stop-Service passport
    Move-Item "$logDir\passport.log" "$logDir\passport-$date.log" -Force
    Start-Service passport
}

# Rotate audit log
if (Test-Path "$logDir\audit.log") {
    Move-Item "$logDir\audit.log" "$logDir\audit-$date.log" -Force
}

# Compress old logs
Get-ChildItem "$logDir\*.log" | Where-Object {
    $_.Name -match "\d{8}" -and $_.LastWriteTime -lt (Get-Date).AddDays(-1)
} | ForEach-Object {
    Compress-Archive -Path $_.FullName -DestinationPath "$($_.FullName).zip" -Force
    Remove-Item $_.FullName
}

# Delete logs older than 30 days
Get-ChildItem "$logDir\*.zip" | Where-Object {
    $_.LastWriteTime -lt (Get-Date).AddDays(-30)
} | Remove-Item
```

Schedule it via Task Scheduler:

```powershell
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -File C:\ProgramData\passport\rotate-logs.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At "02:00AM"
Register-ScheduledTask -TaskName "PassPort Log Rotation" -Action $action -Trigger $trigger `
    -RunLevel Highest -User "SYSTEM"
```

**Option 2: Use stdout logging only**

On Windows, rely on stdout logging captured by the Windows Service Manager or NSSM, which handles rotation automatically. Set `logging.file.path` to empty and let the service wrapper manage output.

---

## 19. API and Health Checks

PassPort exposes two health check endpoints that are exempt from CSRF protection and authentication. These are designed for load balancers, monitoring systems, and orchestrators.

### Liveness Probe

```
GET /healthz
```

Returns `200 OK` if the process is running. This endpoint always succeeds and performs no dependency checks.

**Response:**
```json
{"status": "ok"}
```

### Readiness Probe

```
GET /readyz
```

Returns `200 OK` if the application is ready to serve traffic. Checks:
1. Database is reachable (ping)
2. All database migrations have been applied

**Success response (200):**
```json
{"status": "ready"}
```

**Failure response (503):**
```json
{"status": "not ready", "error": "migrations not complete"}
```

### Usage Examples

**Kubernetes:**
```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8443
    scheme: HTTPS
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /readyz
    port: 8443
    scheme: HTTPS
  periodSeconds: 5
```

**systemd healthcheck (via ExecStartPost or monitoring script):**
```bash
# -k skips verification of the self-signed certificate generated at install time
curl -skf https://localhost:8443/readyz || exit 1
```

**HAProxy:**
```
option httpchk GET /readyz
http-check expect status 200
```

Adjust the port and scheme if you changed `server.addr` or run without TLS.

## 20. Backup & Migration

PassPort provides tools for backing up configuration and migrating to a new installation. There are two modes:

- **Backup** — keeps secrets encrypted (for same-system restore where the master key stays the same)
- **Export** — decrypts secrets to plaintext (for migration to a new system with a different master key)

### What's Included

Both backup and export include all configuration data:

| Data | Included |
|------|----------|
| Local admin accounts | Yes (password hashes, not plaintext) |
| Identity providers | Yes (config + credentials) |
| Provider groups + arrangement | Yes (matched by group name on import) |
| Attribute mappings | Yes |
| Correlation rules | Yes |
| Password expiration config + filters | Yes |
| Report configs + filters | Yes |
| Admin groups | Yes |
| User-IDP mappings | Yes |
| SMTP configuration + credentials | Yes |
| MFA providers + credentials | Yes |
| Branding settings | Yes |
| Email templates | Yes |

**Not included:** sessions (transient), audit log (historical, can be large), schema migrations (auto-managed).

### Command-Line Backup (Secrets Stay Encrypted)

Use `-backup` to create a backup file with secrets preserved as encrypted blobs. This is ideal for scheduled backups and disaster recovery where you'll restore to the same system (or one with the same master key).

```bash
passport -config config.yaml -backup /path/to/passport-backup.json
```

The application opens the database, runs any pending migrations, writes the backup file, and exits without starting the server. The file is created with `0600` permissions.

**Scheduling automated backups with cron:**

```bash
# Daily backup at 2 AM
0 2 * * * /opt/passport/bin/passport -config /opt/passport/config.yaml -backup /opt/passport/backups/passport-$(date +\%Y\%m\%d).json
```

### Command-Line Export (Secrets Decrypted)

Use `-export` to create a migration file with all secrets decrypted to plaintext JSON. This is for migrating to a new installation with a different master encryption key.

```bash
passport -config config.yaml -export /path/to/passport-export.json
```

> **Security warning:** The export file contains plaintext credentials (IDP service account passwords, SMTP credentials, MFA secrets). Handle it securely — transfer via encrypted channel and delete after import.

### Command-Line Import

Use `-import` to import a backup or export file. The application detects the file type automatically:

- **Backup file** (`secrets_encrypted: true`): stores encrypted blobs as-is (requires same master key)
- **Export file** (`secrets_encrypted: false`): re-encrypts plaintext secrets with the local master key

```bash
passport -config config.yaml -import /path/to/passport-backup.json
```

Import is additive — existing records are updated (upserted), new records are created. It does not delete records that aren't in the import file.

### Web UI Export/Import

Admins can also export and import from the web interface:

1. Go to **Admin > Import/Export**
2. **Export:** Click "Download Export" to download a JSON file (secrets decrypted)
3. **Import:** Upload a JSON file and select which sections to import using the checkboxes:
   - Identity Providers
   - Admin Groups
   - User Mappings
   - SMTP Configuration
   - MFA Providers
   - Branding
   - Email Templates
   - Local Admins

The web UI import shows a results summary of what was imported and any errors.

### Migration Workflow

To migrate PassPort to a new server:

1. **On the old server:** Export the configuration
   ```bash
   passport -config config.yaml -export passport-migration.json
   ```

2. **Transfer the file** to the new server (via scp, rsync, etc.)

3. **On the new server:** Install PassPort and generate a new master key
   ```bash
   sudo bash deploy/install.sh
   ```

4. **Import the configuration:**
   ```bash
   cd /opt/passport
   sudo -u passport bin/passport -config config.yaml -import /path/to/passport-migration.json
   ```

5. **Start the service:**
   ```bash
   sudo systemctl start passport
   ```

6. **Verify:** Log in and check that all IDPs, SMTP, MFA, and branding are intact.

7. **Clean up:** Delete the export file from both servers.

### Backup File Format

The backup/export file is JSON with this top-level structure:

```json
{
  "version": 1,
  "exported_at": "2026-03-28T12:00:00Z",
  "secrets_encrypted": false,
  "local_admins": [...],
  "identity_providers": [...],
  "admin_groups": [...],
  "user_mappings": [...],
  "smtp_config": {...},
  "mfa_providers": [...],
  "branding": {...},
  "email_templates": [...]
}
```

The `secrets_encrypted` field indicates whether secret values are plaintext JSON (`false`, from `-export` or web UI) or base64-encoded encrypted blobs (`true`, from `-backup`).

### Uploaded Files

Logo files (branding logo, IDP logos) are stored in the `uploads/` directory and are **not included** in the export. Copy the `uploads/` directory separately if you need to preserve logos:

```bash
rsync -a /opt/passport/uploads/ newserver:/opt/passport/uploads/
```
