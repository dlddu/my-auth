-- 008_add_revoked_tokens.sql
-- Adds a revoked_tokens table implementing the JWT jti blacklist pattern.
-- When an access token (JWT) is revoked via POST /oauth2/revoke (RFC 7009),
-- its jti claim is recorded here so that stateless JWT verification can
-- detect revoked tokens by checking this table.

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti         TEXT PRIMARY KEY,
    revoked_at  DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
