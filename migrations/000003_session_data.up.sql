-- 000003_session_data.up.sql
-- Add request_data and request_id columns to store serialised fosite Requester
-- objects. These columns allow the storage layer to reconstruct full
-- fosite.Requester values on Get operations.
--
-- NOTE: the tokens table already has request_id from migration 000001.

ALTER TABLE authorization_codes ADD COLUMN request_id   TEXT NOT NULL DEFAULT '';
ALTER TABLE authorization_codes ADD COLUMN request_data TEXT NOT NULL DEFAULT '{}';

ALTER TABLE tokens ADD COLUMN request_data TEXT NOT NULL DEFAULT '{}';

ALTER TABLE refresh_tokens ADD COLUMN request_id   TEXT NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN request_data TEXT NOT NULL DEFAULT '{}';

ALTER TABLE sessions ADD COLUMN request_data TEXT NOT NULL DEFAULT '{}';
