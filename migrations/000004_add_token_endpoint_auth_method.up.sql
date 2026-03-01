-- 000004_add_token_endpoint_auth_method.sql
-- Add token_endpoint_auth_method column to clients table so that fosite's
-- DefaultOpenIDConnectClient.GetTokenEndpointAuthMethod() value is persisted
-- and retrieved correctly. Defaults to 'client_secret_basic' to match the
-- most common authentication method used by existing clients.

ALTER TABLE clients ADD COLUMN token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic';
