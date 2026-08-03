-- Provider groups: named sections that identity providers are arranged into on
-- the login page and dashboard.
--
-- Numbered 009 because version 008 was already recorded in deployed databases by
-- a superseded idp_sort_order migration. Version numbers are never reused: the
-- runner keys off them, so a replaced file is skipped in silence.
--
-- Purely additive. The new table starts empty and both new columns on
-- identity_providers are nullable or defaulted, so every existing provider
-- stays ungrouped and keeps rendering exactly as it did before the upgrade.
CREATE TABLE IF NOT EXISTS idp_groups (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    icon          TEXT NOT NULL DEFAULT '',
    collapsible   INTEGER NOT NULL DEFAULT 0,
    display_order INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Deleting a group must not delete its providers, so the reference is cleared
-- instead and they fall back to the ungrouped section.
ALTER TABLE identity_providers
    ADD COLUMN group_id INTEGER REFERENCES idp_groups(id) ON DELETE SET NULL;

ALTER TABLE identity_providers
    ADD COLUMN display_order INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_identity_providers_group
    ON identity_providers(group_id, display_order);
