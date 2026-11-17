-- Run ONCE in Cloudflare D1 Console for the existing wedding-guestbook database.
-- Keeps all existing messages; older messages remain read-only.
ALTER TABLE guestbook ADD COLUMN password_salt TEXT;
ALTER TABLE guestbook ADD COLUMN password_hash TEXT;
