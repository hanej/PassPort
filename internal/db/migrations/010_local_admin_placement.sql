-- Placement of the built-in Local Admin card on the login page.
--
-- Local Admin is a reserved provider ID with no identity_providers row, so it
-- has nowhere to keep a group_id/display_order. This singleton table gives it
-- one, letting it be arranged alongside real providers.
CREATE TABLE IF NOT EXISTS local_admin_placement (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    group_id      INTEGER REFERENCES idp_groups(id) ON DELETE SET NULL,
    display_order INTEGER NOT NULL DEFAULT 0
);
