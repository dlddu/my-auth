-- 000005_add_pkce_sessions.down.sql
-- Revert 000005: drop pkce_codes table.
-- Note: SQLite does not support ALTER TABLE DROP COLUMN portably, so the
-- is_public column added to clients is not removed in this down migration.

DROP TABLE IF EXISTS pkce_codes;
