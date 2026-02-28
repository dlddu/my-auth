-- 000003_add_session_data.down.sql
-- SQLite does not support DROP COLUMN in older versions; recreate the tables.
-- For simplicity we drop and recreate each affected table.

CREATE TABLE tokens_new (
    signature   TEXT PRIMARY KEY,
    request_id  TEXT NOT NULL,
    client_id   TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    subject     TEXT NOT NULL,
    scopes      TEXT NOT NULL,
    expires_at  DATETIME NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
INSERT INTO tokens_new SELECT signature, request_id, client_id, subject, scopes, expires_at, created_at FROM tokens;
DROP TABLE tokens;
ALTER TABLE tokens_new RENAME TO tokens;

CREATE TABLE authorization_codes_new (
    code         TEXT PRIMARY KEY,
    client_id    TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    subject      TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scopes       TEXT NOT NULL,
    expires_at   DATETIME NOT NULL,
    used         INTEGER NOT NULL DEFAULT 0,
    created_at   DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
INSERT INTO authorization_codes_new SELECT code, client_id, subject, redirect_uri, scopes, expires_at, used, created_at FROM authorization_codes;
DROP TABLE authorization_codes;
ALTER TABLE authorization_codes_new RENAME TO authorization_codes;

CREATE TABLE refresh_tokens_new (
    signature  TEXT PRIMARY KEY,
    client_id  TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    subject    TEXT NOT NULL,
    scopes     TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
INSERT INTO refresh_tokens_new SELECT signature, client_id, subject, scopes, expires_at, revoked, created_at FROM refresh_tokens;
DROP TABLE refresh_tokens;
ALTER TABLE refresh_tokens_new RENAME TO refresh_tokens;

CREATE TABLE sessions_new (
    id         TEXT PRIMARY KEY,
    client_id  TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    subject    TEXT NOT NULL,
    scopes     TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
INSERT INTO sessions_new SELECT id, client_id, subject, scopes, expires_at, created_at FROM sessions;
DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;
