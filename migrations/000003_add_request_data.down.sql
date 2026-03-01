-- 000003_add_request_data.down.sql
-- SQLite does not support DROP COLUMN before 3.35.0.
-- Since modernc.org/sqlite bundles SQLite 3.46+ this is safe.

ALTER TABLE sessions DROP COLUMN request_data;
ALTER TABLE refresh_tokens DROP COLUMN access_token_signature;
ALTER TABLE refresh_tokens DROP COLUMN request_data;
ALTER TABLE tokens DROP COLUMN request_data;
ALTER TABLE authorization_codes DROP COLUMN request_data;
