-- Stores warnings from the correlation engine (e.g. ambiguous multi-match)
-- so the dashboard can surface them to the user.
CREATE TABLE IF NOT EXISTS correlation_warnings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    auth_username TEXT NOT NULL,
    target_idp_id TEXT NOT NULL,
    warning_type  TEXT NOT NULL,           -- e.g. "ambiguous_match"
    message       TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(auth_username, target_idp_id)
);
