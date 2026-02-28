-- 000003_add_session_data.up.sql
-- Add session_data column to store serialized fosite.Requester JSON,
-- and request_id to tables that need it for revocation by request ID.

ALTER TABLE tokens ADD COLUMN session_data TEXT NOT NULL DEFAULT '{}';
ALTER TABLE authorization_codes ADD COLUMN session_data TEXT NOT NULL DEFAULT '{}';
ALTER TABLE authorization_codes ADD COLUMN request_id TEXT NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN session_data TEXT NOT NULL DEFAULT '{}';
ALTER TABLE refresh_tokens ADD COLUMN request_id TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN session_data TEXT NOT NULL DEFAULT '{}';
ALTER TABLE sessions ADD COLUMN request_id TEXT NOT NULL DEFAULT '';
