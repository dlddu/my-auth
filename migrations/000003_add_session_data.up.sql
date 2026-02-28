-- 003_add_session_data.sql
-- Add session_data column to store serialized fosite.Request JSON for all token types.

ALTER TABLE authorization_codes ADD COLUMN session_data TEXT NOT NULL DEFAULT '';
ALTER TABLE authorization_codes ADD COLUMN request_id TEXT NOT NULL DEFAULT '';
ALTER TABLE authorization_codes ADD COLUMN granted_scopes TEXT NOT NULL DEFAULT '';

ALTER TABLE tokens ADD COLUMN session_data TEXT NOT NULL DEFAULT '';
ALTER TABLE tokens ADD COLUMN granted_scopes TEXT NOT NULL DEFAULT '';

ALTER TABLE refresh_tokens ADD COLUMN session_data TEXT NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN request_id TEXT NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN granted_scopes TEXT NOT NULL DEFAULT '';

ALTER TABLE sessions ADD COLUMN session_data TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN request_id TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN scopes_data TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN granted_scopes TEXT NOT NULL DEFAULT '';
