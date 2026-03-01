-- Revert 000004: SQLite does not support DROP COLUMN on older versions,
-- so we recreate the table without the token_endpoint_auth_method column.

CREATE TABLE clients_backup (
    id              TEXT PRIMARY KEY,
    secret          TEXT NOT NULL,
    redirect_uris   TEXT NOT NULL,
    grant_types     TEXT NOT NULL,
    response_types  TEXT NOT NULL,
    scopes          TEXT NOT NULL,
    created_at      DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT INTO clients_backup (id, secret, redirect_uris, grant_types, response_types, scopes, created_at, updated_at)
SELECT id, secret, redirect_uris, grant_types, response_types, scopes, created_at, updated_at FROM clients;

DROP TABLE clients;

ALTER TABLE clients_backup RENAME TO clients;
