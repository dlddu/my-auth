-- 000007_add_refresh_token_request_id.up.sql
-- Add a dedicated request_id column to refresh_tokens so that
-- RevokeRefreshToken can use a parameterized WHERE clause instead
-- of a LIKE-based lookup inside the request_data JSON blob.

ALTER TABLE refresh_tokens ADD COLUMN request_id TEXT NOT NULL DEFAULT '';
