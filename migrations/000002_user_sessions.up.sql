CREATE TABLE IF NOT EXISTS user_sessions (
    id         TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
