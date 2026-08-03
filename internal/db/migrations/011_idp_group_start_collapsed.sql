-- Whether a collapsible group renders collapsed on first paint.
--
-- Only meaningful when collapsible = 1; a group users cannot expand must not
-- start hidden.
ALTER TABLE idp_groups ADD COLUMN start_collapsed INTEGER NOT NULL DEFAULT 0;
