-- 000001_init.down.sql
-- Rollback initial schema for my-auth OAuth2/OIDC Authorization Server

DROP TABLE IF EXISTS device_codes;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS authorization_codes;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS tokens;
DROP TABLE IF EXISTS clients;
