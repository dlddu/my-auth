-- 000007_add_refresh_token_request_id.down.sql

ALTER TABLE refresh_tokens DROP COLUMN request_id;
