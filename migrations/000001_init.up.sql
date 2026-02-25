-- 001_init.sql
-- Initial schema for my-auth OAuth2/OIDC Authorization Server
-- All tables use CREATE TABLE IF NOT EXISTS for idempotent migration.

CREATE TABLE IF NOT EXISTS clients (
    id              TEXT PRIMARY KEY,
    secret          TEXT NOT NULL,
    redirect_uris   TEXT NOT NULL,  -- JSON array
    grant_types     TEXT NOT NULL,  -- JSON array
    response_types  TEXT NOT NULL,  -- JSON array
    scopes          TEXT NOT NULL,  -- space-separated
    created_at      DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS tokens (
    signature       TEXT PRIMARY KEY,
    request_id      TEXT NOT NULL,
    client_id       TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    subject         TEXT NOT NULL,
    scopes          TEXT NOT NULL,  -- space-separated
    expires_at      DATETIME NOT NULL,
    created_at      DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    subject         TEXT NOT NULL,
    scopes          TEXT NOT NULL,  -- space-separated
    expires_at      DATETIME NOT NULL,
    created_at      DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS authorization_codes (
    code            TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    subject         TEXT NOT NULL,
    redirect_uri    TEXT NOT NULL,
    scopes          TEXT NOT NULL,  -- space-separated
    expires_at      DATETIME NOT NULL,
    used            INTEGER NOT NULL DEFAULT 0,
    created_at      DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    signature       TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    subject         TEXT NOT NULL,
    scopes          TEXT NOT NULL,  -- space-separated
    expires_at      DATETIME NOT NULL,
    revoked         INTEGER NOT NULL DEFAULT 0,
    created_at      DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS device_codes (
    device_code     TEXT PRIMARY KEY,
    user_code       TEXT NOT NULL UNIQUE,
    client_id       TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scopes          TEXT NOT NULL,  -- space-separated
    expires_at      DATETIME NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending', -- pending | approved | denied
    subject         TEXT,
    created_at      DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
