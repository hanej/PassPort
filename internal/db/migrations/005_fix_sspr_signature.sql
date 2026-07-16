-- Fix email templates that were seeded before the app was renamed from
-- SSPR to PassPort. New template defaults use INSERT OR IGNORE, so
-- instances that already had these rows never picked up the rename.
UPDATE email_templates
SET subject = REPLACE(subject, 'SSPR', 'PassPort')
WHERE subject LIKE '%SSPR%';

UPDATE email_templates
SET body_html = REPLACE(body_html, 'SSPR', 'PassPort')
WHERE body_html LIKE '%SSPR%';
