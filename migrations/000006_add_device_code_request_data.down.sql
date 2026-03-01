-- 000006_add_device_code_request_data.down.sql
-- SQLite does not support DROP COLUMN in older versions; recreate the table
-- without the request_data column.

CREATE TABLE IF NOT EXISTS device_codes_backup (
    device_code  TEXT PRIMARY KEY,
    user_code    TEXT NOT NULL UNIQUE,
    client_id    TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scopes       TEXT NOT NULL,
    expires_at   DATETIME NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    subject      TEXT,
    created_at   DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT INTO device_codes_backup SELECT device_code, user_code, client_id, scopes, expires_at, status, subject, created_at FROM device_codes;
DROP TABLE device_codes;
ALTER TABLE device_codes_backup RENAME TO device_codes;
