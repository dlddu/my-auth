-- Rollback: SQLite does not support DROP COLUMN in all versions.
-- This migration cannot be cleanly reverted without recreating the tables.
SELECT 1;
