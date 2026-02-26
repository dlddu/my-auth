-- Seed the test OAuth2 client for e2e tests.
-- This matches the test client defined in internal/testhelper/seed.go.
INSERT OR IGNORE INTO clients
    (id, secret, redirect_uris, grant_types, response_types, scopes)
VALUES
    ('test-client',
     '$2a$10$W56btv7OINIPA/cdcVu8j.JfidjXwBpLE3CkJUlAfK.XKmNr/8olS',
     '["http://localhost:9999/callback"]',
     '["authorization_code","refresh_token"]',
     '["code"]',
     'openid profile email offline_access');
