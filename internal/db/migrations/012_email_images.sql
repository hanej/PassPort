-- Image library for email templates. Files live in uploads/email-images/;
-- this table holds the display name and metadata for each one.
CREATE TABLE IF NOT EXISTS email_images (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL,
    filename     TEXT    NOT NULL UNIQUE,
    content_type TEXT    NOT NULL,
    size_bytes   INTEGER NOT NULL DEFAULT 0,
    width        INTEGER NOT NULL DEFAULT 0,
    height       INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
