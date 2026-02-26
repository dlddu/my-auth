package testhelper

import (
	"database/sql"
	"testing"
)

// testClientID is the OAuth2 client ID used in all integration tests.
const testClientID = "test-client"

// testClientSecret is the plain-text secret for the test OAuth2 client.
const testClientSecret = "test-secret"

// testClientSecretHash is the pre-computed bcrypt hash of "test-secret" with cost 10.
// Pre-computed to avoid importing golang.org/x/crypto/bcrypt as a direct dependency
// and to speed up test setup.
// Plain-text: "test-secret"
const testClientSecretHash = "$2a$10$W56btv7OINIPA/cdcVu8j.JfidjXwBpLE3CkJUlAfK.XKmNr/8olS"

// testRedirectURI is the redirect URI registered for the test OAuth2 client.
const testRedirectURI = "http://localhost:9999/callback"

// testClientScopes is the space-separated scope list for the test OAuth2 client.
const testClientScopes = "openid profile email"

// SeedTestClient inserts the canonical test OAuth2 client into the clients
// table of db. It is idempotent: if the client already exists the insert is
// silently skipped via INSERT OR IGNORE.
//
// The client secret is stored as a pre-computed bcrypt hash so that fosite's
// bcrypt-based secret comparison works correctly during the token endpoint
// exchange.
//
// Call this helper in any test that exercises OAuth2 flows so that fosite's
// ClientStore can resolve "test-client".
func SeedTestClient(t *testing.T, db *sql.DB) {
	t.Helper()

	_, err := db.Exec(
		`INSERT OR IGNORE INTO clients
		    (id, secret, redirect_uris, grant_types, response_types, scopes)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		testClientID,
		testClientSecretHash,
		`["http://localhost:9999/callback"]`,
		`["authorization_code","refresh_token"]`,
		`["code"]`,
		testClientScopes,
	)
	if err != nil {
		t.Fatalf("testhelper.SeedTestClient: insert test client: %v", err)
	}
}
