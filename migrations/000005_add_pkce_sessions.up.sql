-- 000005_add_pkce_sessions.up.sql
-- Add pkce_codes table for PKCE request session storage and add is_public
-- column to clients table to support public clients (e.g. SPAs using PKCE).

CREATE TABLE IF NOT EXISTS pkce_codes (
    signature       TEXT PRIMARY KEY,
    request_data    TEXT NOT NULL
);

ALTER TABLE clients ADD COLUMN is_public BOOLEAN NOT NULL DEFAULT FALSE;
