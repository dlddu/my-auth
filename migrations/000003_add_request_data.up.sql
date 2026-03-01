-- 000003_add_request_data.sql
-- Add request_data column to store the full serialized fosite.Requester as JSON.
-- Also add access_token_signature to refresh_tokens for token rotation.

ALTER TABLE authorization_codes ADD COLUMN request_data TEXT NOT NULL DEFAULT '{}';
ALTER TABLE tokens ADD COLUMN request_data TEXT NOT NULL DEFAULT '{}';
ALTER TABLE refresh_tokens ADD COLUMN request_data TEXT NOT NULL DEFAULT '{}';
ALTER TABLE refresh_tokens ADD COLUMN access_token_signature TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN request_data TEXT NOT NULL DEFAULT '{}';
