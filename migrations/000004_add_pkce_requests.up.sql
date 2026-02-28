-- 004_add_pkce_requests.sql
-- Add pkce_requests table for PKCE code_challenge storage.

CREATE TABLE IF NOT EXISTS pkce_requests (
    signature       TEXT PRIMARY KEY,
    session_data    TEXT NOT NULL DEFAULT '',
    created_at      DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
