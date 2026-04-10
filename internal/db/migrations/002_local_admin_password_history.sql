-- Track password history for local admin accounts to prevent password reuse.
CREATE TABLE IF NOT EXISTS local_admin_password_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (username) REFERENCES local_admins(username) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_pw_history_username_ts
    ON local_admin_password_history(username, created_at DESC);
